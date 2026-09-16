rule TTP_XOR_WriteProcessMemory_dd7b {
  strings:
    $key_dd7b = { 8a 09 [2] b8 2b [2] be 1e [2] 90 1e [2] af 02 }

  condition:
    any of them
}