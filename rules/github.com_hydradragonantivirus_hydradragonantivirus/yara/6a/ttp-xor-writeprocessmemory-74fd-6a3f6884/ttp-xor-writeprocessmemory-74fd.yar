rule TTP_XOR_WriteProcessMemory_74fd {
  strings:
    $key_74fd = { 23 8f [2] 11 ad [2] 17 98 [2] 39 98 [2] 06 84 }

  condition:
    any of them
}