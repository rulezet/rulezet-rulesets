rule TTP_XOR_WriteProcessMemory_cf17 {
  strings:
    $key_cf17 = { 98 65 [2] aa 47 [2] ac 72 [2] 82 72 [2] bd 6e }

  condition:
    any of them
}