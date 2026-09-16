rule TTP_XOR_WriteProcessMemory_10fd {
  strings:
    $key_10fd = { 47 8f [2] 75 ad [2] 73 98 [2] 5d 98 [2] 62 84 }

  condition:
    any of them
}