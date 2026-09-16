rule TTP_XOR_WriteProcessMemory_0276 {
  strings:
    $key_0276 = { 55 04 [2] 67 26 [2] 61 13 [2] 4f 13 [2] 70 0f }

  condition:
    any of them
}