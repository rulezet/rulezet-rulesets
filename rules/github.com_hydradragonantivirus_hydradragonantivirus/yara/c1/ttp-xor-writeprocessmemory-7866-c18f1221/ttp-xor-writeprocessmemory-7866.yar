rule TTP_XOR_WriteProcessMemory_7866 {
  strings:
    $key_7866 = { 2f 14 [2] 1d 36 [2] 1b 03 [2] 35 03 [2] 0a 1f }

  condition:
    any of them
}