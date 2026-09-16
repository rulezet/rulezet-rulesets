rule TTP_XOR_WriteProcessMemory_2b21 {
  strings:
    $key_2b21 = { 7c 53 [2] 4e 71 [2] 48 44 [2] 66 44 [2] 59 58 }

  condition:
    any of them
}