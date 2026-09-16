rule TTP_XOR_WriteProcessMemory_cf19 {
  strings:
    $key_cf19 = { 98 6b [2] aa 49 [2] ac 7c [2] 82 7c [2] bd 60 }

  condition:
    any of them
}