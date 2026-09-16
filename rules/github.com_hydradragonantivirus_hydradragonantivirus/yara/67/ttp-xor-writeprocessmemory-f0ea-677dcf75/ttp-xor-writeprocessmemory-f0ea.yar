rule TTP_XOR_WriteProcessMemory_f0ea {
  strings:
    $key_f0ea = { a7 98 [2] 95 ba [2] 93 8f [2] bd 8f [2] 82 93 }

  condition:
    any of them
}