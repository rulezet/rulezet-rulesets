rule TTP_XOR_WriteProcessMemory_3136 {
  strings:
    $key_3136 = { 66 44 [2] 54 66 [2] 52 53 [2] 7c 53 [2] 43 4f }

  condition:
    any of them
}