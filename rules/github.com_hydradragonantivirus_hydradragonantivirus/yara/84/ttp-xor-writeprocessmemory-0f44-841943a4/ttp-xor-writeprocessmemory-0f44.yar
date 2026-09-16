rule TTP_XOR_WriteProcessMemory_0f44 {
  strings:
    $key_0f44 = { 58 36 [2] 6a 14 [2] 6c 21 [2] 42 21 [2] 7d 3d }

  condition:
    any of them
}