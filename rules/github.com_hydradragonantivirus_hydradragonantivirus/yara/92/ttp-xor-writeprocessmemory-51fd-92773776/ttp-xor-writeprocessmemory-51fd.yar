rule TTP_XOR_WriteProcessMemory_51fd {
  strings:
    $key_51fd = { 06 8f [2] 34 ad [2] 32 98 [2] 1c 98 [2] 23 84 }

  condition:
    any of them
}