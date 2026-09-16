rule TTP_XOR_WriteProcessMemory_3102 {
  strings:
    $key_3102 = { 66 70 [2] 54 52 [2] 52 67 [2] 7c 67 [2] 43 7b }

  condition:
    any of them
}