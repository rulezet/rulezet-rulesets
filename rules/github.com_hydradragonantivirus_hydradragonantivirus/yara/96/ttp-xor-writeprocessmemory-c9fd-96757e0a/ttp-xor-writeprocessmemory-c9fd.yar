rule TTP_XOR_WriteProcessMemory_c9fd {
  strings:
    $key_c9fd = { 9e 8f [2] ac ad [2] aa 98 [2] 84 98 [2] bb 84 }

  condition:
    any of them
}