rule TTP_XOR_WriteProcessMemory_30fd {
  strings:
    $key_30fd = { 67 8f [2] 55 ad [2] 53 98 [2] 7d 98 [2] 42 84 }

  condition:
    any of them
}