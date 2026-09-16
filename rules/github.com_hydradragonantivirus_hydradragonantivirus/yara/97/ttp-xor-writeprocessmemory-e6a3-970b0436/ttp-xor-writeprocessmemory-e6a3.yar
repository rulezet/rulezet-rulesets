rule TTP_XOR_WriteProcessMemory_e6a3 {
  strings:
    $key_e6a3 = { b1 d1 [2] 83 f3 [2] 85 c6 [2] ab c6 [2] 94 da }

  condition:
    any of them
}