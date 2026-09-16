rule TTP_XOR_WriteProcessMemory_cf54 {
  strings:
    $key_cf54 = { 98 26 [2] aa 04 [2] ac 31 [2] 82 31 [2] bd 2d }

  condition:
    any of them
}