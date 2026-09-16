rule TTP_XOR_WriteProcessMemory_cff3 {
  strings:
    $key_cff3 = { 98 81 [2] aa a3 [2] ac 96 [2] 82 96 [2] bd 8a }

  condition:
    any of them
}