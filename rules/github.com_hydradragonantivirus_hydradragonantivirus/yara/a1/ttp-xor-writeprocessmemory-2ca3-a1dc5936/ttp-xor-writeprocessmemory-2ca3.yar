rule TTP_XOR_WriteProcessMemory_2ca3 {
  strings:
    $key_2ca3 = { 7b d1 [2] 49 f3 [2] 4f c6 [2] 61 c6 [2] 5e da }

  condition:
    any of them
}