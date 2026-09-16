rule TTP_XOR_WriteProcessMemory_3644 {
  strings:
    $key_3644 = { 61 36 [2] 53 14 [2] 55 21 [2] 7b 21 [2] 44 3d }

  condition:
    any of them
}