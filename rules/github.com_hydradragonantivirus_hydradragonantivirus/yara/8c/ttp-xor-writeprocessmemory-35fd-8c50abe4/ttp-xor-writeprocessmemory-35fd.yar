rule TTP_XOR_WriteProcessMemory_35fd {
  strings:
    $key_35fd = { 62 8f [2] 50 ad [2] 56 98 [2] 78 98 [2] 47 84 }

  condition:
    any of them
}