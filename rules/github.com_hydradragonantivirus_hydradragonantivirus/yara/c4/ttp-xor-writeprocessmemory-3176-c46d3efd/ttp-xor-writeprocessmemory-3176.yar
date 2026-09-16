rule TTP_XOR_WriteProcessMemory_3176 {
  strings:
    $key_3176 = { 66 04 [2] 54 26 [2] 52 13 [2] 7c 13 [2] 43 0f }

  condition:
    any of them
}