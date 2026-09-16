rule TTP_XOR_WriteProcessMemory_cf38 {
  strings:
    $key_cf38 = { 98 4a [2] aa 68 [2] ac 5d [2] 82 5d [2] bd 41 }

  condition:
    any of them
}