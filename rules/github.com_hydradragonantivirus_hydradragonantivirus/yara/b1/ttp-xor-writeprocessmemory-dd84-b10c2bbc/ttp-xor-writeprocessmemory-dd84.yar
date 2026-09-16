rule TTP_XOR_WriteProcessMemory_dd84 {
  strings:
    $key_dd84 = { 8a f6 [2] b8 d4 [2] be e1 [2] 90 e1 [2] af fd }

  condition:
    any of them
}