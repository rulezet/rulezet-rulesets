rule TTP_XOR_WriteProcessMemory_cf49 {
  strings:
    $key_cf49 = { 98 3b [2] aa 19 [2] ac 2c [2] 82 2c [2] bd 30 }

  condition:
    any of them
}