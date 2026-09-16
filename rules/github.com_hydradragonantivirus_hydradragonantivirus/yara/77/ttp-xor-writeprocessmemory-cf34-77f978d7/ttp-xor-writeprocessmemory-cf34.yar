rule TTP_XOR_WriteProcessMemory_cf34 {
  strings:
    $key_cf34 = { 98 46 [2] aa 64 [2] ac 51 [2] 82 51 [2] bd 4d }

  condition:
    any of them
}