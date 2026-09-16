rule TTP_XOR_WriteProcessMemory_cf64 {
  strings:
    $key_cf64 = { 98 16 [2] aa 34 [2] ac 01 [2] 82 01 [2] bd 1d }

  condition:
    any of them
}