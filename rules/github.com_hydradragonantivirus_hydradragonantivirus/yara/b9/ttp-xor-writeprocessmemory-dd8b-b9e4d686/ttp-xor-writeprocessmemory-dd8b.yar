rule TTP_XOR_WriteProcessMemory_dd8b {
  strings:
    $key_dd8b = { 8a f9 [2] b8 db [2] be ee [2] 90 ee [2] af f2 }

  condition:
    any of them
}