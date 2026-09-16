rule TTP_XOR_WriteProcessMemory_dd90 {
  strings:
    $key_dd90 = { 8a e2 [2] b8 c0 [2] be f5 [2] 90 f5 [2] af e9 }

  condition:
    any of them
}