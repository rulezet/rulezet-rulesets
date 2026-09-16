rule TTP_XOR_WriteProcessMemory_67a3 {
  strings:
    $key_67a3 = { 30 d1 [2] 02 f3 [2] 04 c6 [2] 2a c6 [2] 15 da }

  condition:
    any of them
}