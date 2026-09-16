rule TTP_XOR_WriteProcessMemory_cf69 {
  strings:
    $key_cf69 = { 98 1b [2] aa 39 [2] ac 0c [2] 82 0c [2] bd 10 }

  condition:
    any of them
}