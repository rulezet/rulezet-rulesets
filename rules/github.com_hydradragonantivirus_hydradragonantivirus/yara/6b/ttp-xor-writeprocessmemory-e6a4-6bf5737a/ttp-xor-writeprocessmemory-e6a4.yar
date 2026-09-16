rule TTP_XOR_WriteProcessMemory_e6a4 {
  strings:
    $key_e6a4 = { b1 d6 [2] 83 f4 [2] 85 c1 [2] ab c1 [2] 94 dd }

  condition:
    any of them
}