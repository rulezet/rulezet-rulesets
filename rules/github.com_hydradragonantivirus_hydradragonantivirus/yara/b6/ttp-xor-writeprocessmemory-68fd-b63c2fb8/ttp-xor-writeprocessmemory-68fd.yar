rule TTP_XOR_WriteProcessMemory_68fd {
  strings:
    $key_68fd = { 3f 8f [2] 0d ad [2] 0b 98 [2] 25 98 [2] 1a 84 }

  condition:
    any of them
}