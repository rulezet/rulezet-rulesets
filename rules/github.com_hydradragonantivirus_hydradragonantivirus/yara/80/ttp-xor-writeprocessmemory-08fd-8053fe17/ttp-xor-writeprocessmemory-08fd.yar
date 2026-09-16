rule TTP_XOR_WriteProcessMemory_08fd {
  strings:
    $key_08fd = { 5f 8f [2] 6d ad [2] 6b 98 [2] 45 98 [2] 7a 84 }

  condition:
    any of them
}