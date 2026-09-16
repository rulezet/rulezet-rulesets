rule TTP_XOR_WriteProcessMemory_e2b3 {
  strings:
    $key_e2b3 = { b5 c1 [2] 87 e3 [2] 81 d6 [2] af d6 [2] 90 ca }

  condition:
    any of them
}