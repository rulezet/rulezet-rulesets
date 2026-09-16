rule TTP_XOR_WriteProcessMemory_cf28 {
  strings:
    $key_cf28 = { 98 5a [2] aa 78 [2] ac 4d [2] 82 4d [2] bd 51 }

  condition:
    any of them
}