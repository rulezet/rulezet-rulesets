rule TTP_XOR_WriteProcessMemory_dd4b {
  strings:
    $key_dd4b = { 8a 39 [2] b8 1b [2] be 2e [2] 90 2e [2] af 32 }

  condition:
    any of them
}