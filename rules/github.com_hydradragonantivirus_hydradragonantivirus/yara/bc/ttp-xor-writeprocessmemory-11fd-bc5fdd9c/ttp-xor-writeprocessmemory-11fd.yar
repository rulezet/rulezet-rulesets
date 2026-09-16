rule TTP_XOR_WriteProcessMemory_11fd {
  strings:
    $key_11fd = { 46 8f [2] 74 ad [2] 72 98 [2] 5c 98 [2] 63 84 }

  condition:
    any of them
}