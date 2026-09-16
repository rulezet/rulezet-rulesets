rule TTP_XOR_WriteProcessMemory_17fd {
  strings:
    $key_17fd = { 40 8f [2] 72 ad [2] 74 98 [2] 5a 98 [2] 65 84 }

  condition:
    any of them
}