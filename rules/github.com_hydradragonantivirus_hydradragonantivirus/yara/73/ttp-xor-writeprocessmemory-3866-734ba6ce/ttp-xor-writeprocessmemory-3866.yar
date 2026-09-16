rule TTP_XOR_WriteProcessMemory_3866 {
  strings:
    $key_3866 = { 6f 14 [2] 5d 36 [2] 5b 03 [2] 75 03 [2] 4a 1f }

  condition:
    any of them
}