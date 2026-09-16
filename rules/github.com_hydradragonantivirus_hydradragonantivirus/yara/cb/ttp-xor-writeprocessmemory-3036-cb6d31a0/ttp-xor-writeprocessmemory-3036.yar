rule TTP_XOR_WriteProcessMemory_3036 {
  strings:
    $key_3036 = { 67 44 [2] 55 66 [2] 53 53 [2] 7d 53 [2] 42 4f }

  condition:
    any of them
}