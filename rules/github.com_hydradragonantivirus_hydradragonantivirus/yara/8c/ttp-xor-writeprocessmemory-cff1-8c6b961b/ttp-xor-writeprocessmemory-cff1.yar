rule TTP_XOR_WriteProcessMemory_cff1 {
  strings:
    $key_cff1 = { 98 83 [2] aa a1 [2] ac 94 [2] 82 94 [2] bd 88 }

  condition:
    any of them
}