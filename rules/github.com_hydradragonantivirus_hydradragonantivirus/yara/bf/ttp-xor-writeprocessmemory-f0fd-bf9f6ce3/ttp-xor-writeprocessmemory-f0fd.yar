rule TTP_XOR_WriteProcessMemory_f0fd {
  strings:
    $key_f0fd = { a7 8f [2] 95 ad [2] 93 98 [2] bd 98 [2] 82 84 }

  condition:
    any of them
}