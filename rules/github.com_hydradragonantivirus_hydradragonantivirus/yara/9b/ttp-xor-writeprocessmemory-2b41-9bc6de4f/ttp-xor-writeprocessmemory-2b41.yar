rule TTP_XOR_WriteProcessMemory_2b41 {
  strings:
    $key_2b41 = { 7c 33 [2] 4e 11 [2] 48 24 [2] 66 24 [2] 59 38 }

  condition:
    any of them
}