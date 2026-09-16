rule TTP_XOR_WriteProcessMemory_cf36 {
  strings:
    $key_cf36 = { 98 44 [2] aa 66 [2] ac 53 [2] 82 53 [2] bd 4f }

  condition:
    any of them
}