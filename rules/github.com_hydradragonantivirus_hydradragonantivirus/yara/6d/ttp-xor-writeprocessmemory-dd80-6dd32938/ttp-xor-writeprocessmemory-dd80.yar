rule TTP_XOR_WriteProcessMemory_dd80 {
  strings:
    $key_dd80 = { 8a f2 [2] b8 d0 [2] be e5 [2] 90 e5 [2] af f9 }

  condition:
    any of them
}