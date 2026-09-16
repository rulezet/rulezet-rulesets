rule TTP_XOR_WriteProcessMemory_cf04 {
  strings:
    $key_cf04 = { 98 76 [2] aa 54 [2] ac 61 [2] 82 61 [2] bd 7d }

  condition:
    any of them
}