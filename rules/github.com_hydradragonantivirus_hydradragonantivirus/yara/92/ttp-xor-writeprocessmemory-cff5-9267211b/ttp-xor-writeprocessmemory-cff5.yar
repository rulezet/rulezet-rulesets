rule TTP_XOR_WriteProcessMemory_cff5 {
  strings:
    $key_cff5 = { 98 87 [2] aa a5 [2] ac 90 [2] 82 90 [2] bd 8c }

  condition:
    any of them
}