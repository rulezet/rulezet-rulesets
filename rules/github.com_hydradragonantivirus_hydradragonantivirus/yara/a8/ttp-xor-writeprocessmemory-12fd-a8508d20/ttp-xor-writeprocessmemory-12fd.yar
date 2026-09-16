rule TTP_XOR_WriteProcessMemory_12fd {
  strings:
    $key_12fd = { 45 8f [2] 77 ad [2] 71 98 [2] 5f 98 [2] 60 84 }

  condition:
    any of them
}