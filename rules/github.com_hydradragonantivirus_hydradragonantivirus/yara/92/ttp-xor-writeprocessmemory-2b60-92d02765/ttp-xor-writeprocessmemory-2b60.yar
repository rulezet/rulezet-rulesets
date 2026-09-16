rule TTP_XOR_WriteProcessMemory_2b60 {
  strings:
    $key_2b60 = { 7c 12 [2] 4e 30 [2] 48 05 [2] 66 05 [2] 59 19 }

  condition:
    any of them
}