rule TTP_XOR_WriteProcessMemory_50fd {
  strings:
    $key_50fd = { 07 8f [2] 35 ad [2] 33 98 [2] 1d 98 [2] 22 84 }

  condition:
    any of them
}