rule TTP_XOR_WriteProcessMemory_5866 {
  strings:
    $key_5866 = { 0f 14 [2] 3d 36 [2] 3b 03 [2] 15 03 [2] 2a 1f }

  condition:
    any of them
}