rule TTP_XOR_WriteProcessMemory_dd82 {
  strings:
    $key_dd82 = { 8a f0 [2] b8 d2 [2] be e7 [2] 90 e7 [2] af fb }

  condition:
    any of them
}