rule TTP_XOR_WriteProcessMemory_cf22 {
  strings:
    $key_cf22 = { 98 50 [2] aa 72 [2] ac 47 [2] 82 47 [2] bd 5b }

  condition:
    any of them
}