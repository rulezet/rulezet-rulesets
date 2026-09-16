rule TTP_XOR_WriteProcessMemory_4866 {
  strings:
    $key_4866 = { 1f 14 [2] 2d 36 [2] 2b 03 [2] 05 03 [2] 3a 1f }

  condition:
    any of them
}