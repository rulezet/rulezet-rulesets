rule TTP_XOR_WriteProcessMemory_cf10 {
  strings:
    $key_cf10 = { 98 62 [2] aa 40 [2] ac 75 [2] 82 75 [2] bd 69 }

  condition:
    any of them
}