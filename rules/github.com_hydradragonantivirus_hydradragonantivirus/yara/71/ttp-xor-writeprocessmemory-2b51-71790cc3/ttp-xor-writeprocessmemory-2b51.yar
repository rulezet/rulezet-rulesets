rule TTP_XOR_WriteProcessMemory_2b51 {
  strings:
    $key_2b51 = { 7c 23 [2] 4e 01 [2] 48 34 [2] 66 34 [2] 59 28 }

  condition:
    any of them
}