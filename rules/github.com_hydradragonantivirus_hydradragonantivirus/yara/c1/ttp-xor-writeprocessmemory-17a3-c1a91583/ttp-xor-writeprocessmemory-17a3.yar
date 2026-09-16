rule TTP_XOR_WriteProcessMemory_17a3 {
  strings:
    $key_17a3 = { 40 d1 [2] 72 f3 [2] 74 c6 [2] 5a c6 [2] 65 da }

  condition:
    any of them
}