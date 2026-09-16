rule TTP_XOR_WriteProcessMemory_2b31 {
  strings:
    $key_2b31 = { 7c 43 [2] 4e 61 [2] 48 54 [2] 66 54 [2] 59 48 }

  condition:
    any of them
}