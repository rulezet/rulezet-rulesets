rule TTP_XOR_WriteProcessMemory_07fd {
  strings:
    $key_07fd = { 50 8f [2] 62 ad [2] 64 98 [2] 4a 98 [2] 75 84 }

  condition:
    any of them
}