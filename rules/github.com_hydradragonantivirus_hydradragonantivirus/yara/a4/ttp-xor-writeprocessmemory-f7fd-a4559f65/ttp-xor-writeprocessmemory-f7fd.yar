rule TTP_XOR_WriteProcessMemory_f7fd {
  strings:
    $key_f7fd = { a0 8f [2] 92 ad [2] 94 98 [2] ba 98 [2] 85 84 }

  condition:
    any of them
}