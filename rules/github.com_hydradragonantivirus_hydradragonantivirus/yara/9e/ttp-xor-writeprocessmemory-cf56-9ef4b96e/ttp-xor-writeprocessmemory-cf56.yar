rule TTP_XOR_WriteProcessMemory_cf56 {
  strings:
    $key_cf56 = { 98 24 [2] aa 06 [2] ac 33 [2] 82 33 [2] bd 2f }

  condition:
    any of them
}