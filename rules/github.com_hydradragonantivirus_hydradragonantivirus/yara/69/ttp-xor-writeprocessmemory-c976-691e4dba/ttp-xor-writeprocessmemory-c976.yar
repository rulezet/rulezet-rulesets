rule TTP_XOR_WriteProcessMemory_c976 {
  strings:
    $key_c976 = { 9e 04 [2] ac 26 [2] aa 13 [2] 84 13 [2] bb 0f }

  condition:
    any of them
}