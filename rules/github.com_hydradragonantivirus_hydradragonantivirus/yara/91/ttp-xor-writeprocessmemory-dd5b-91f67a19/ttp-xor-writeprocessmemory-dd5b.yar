rule TTP_XOR_WriteProcessMemory_dd5b {
  strings:
    $key_dd5b = { 8a 29 [2] b8 0b [2] be 3e [2] 90 3e [2] af 22 }

  condition:
    any of them
}