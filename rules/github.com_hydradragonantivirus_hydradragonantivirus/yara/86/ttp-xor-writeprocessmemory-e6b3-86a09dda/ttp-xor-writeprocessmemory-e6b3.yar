rule TTP_XOR_WriteProcessMemory_e6b3 {
  strings:
    $key_e6b3 = { b1 c1 [2] 83 e3 [2] 85 d6 [2] ab d6 [2] 94 ca }

  condition:
    any of them
}