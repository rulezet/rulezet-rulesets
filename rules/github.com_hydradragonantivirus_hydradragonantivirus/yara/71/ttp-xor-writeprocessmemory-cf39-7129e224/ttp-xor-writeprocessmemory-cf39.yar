rule TTP_XOR_WriteProcessMemory_cf39 {
  strings:
    $key_cf39 = { 98 4b [2] aa 69 [2] ac 5c [2] 82 5c [2] bd 40 }

  condition:
    any of them
}