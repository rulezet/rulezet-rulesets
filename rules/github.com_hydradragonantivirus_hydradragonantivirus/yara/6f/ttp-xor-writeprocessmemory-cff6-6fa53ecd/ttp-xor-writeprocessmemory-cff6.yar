rule TTP_XOR_WriteProcessMemory_cff6 {
  strings:
    $key_cff6 = { 98 84 [2] aa a6 [2] ac 93 [2] 82 93 [2] bd 8f }

  condition:
    any of them
}