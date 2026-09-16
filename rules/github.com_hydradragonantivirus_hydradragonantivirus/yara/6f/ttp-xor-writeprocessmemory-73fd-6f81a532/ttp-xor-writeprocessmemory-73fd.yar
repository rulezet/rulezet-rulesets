rule TTP_XOR_WriteProcessMemory_73fd {
  strings:
    $key_73fd = { 24 8f [2] 16 ad [2] 10 98 [2] 3e 98 [2] 01 84 }

  condition:
    any of them
}