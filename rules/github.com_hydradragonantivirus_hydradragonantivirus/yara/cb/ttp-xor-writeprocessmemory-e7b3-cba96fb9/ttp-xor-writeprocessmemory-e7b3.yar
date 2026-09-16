rule TTP_XOR_WriteProcessMemory_e7b3 {
  strings:
    $key_e7b3 = { b0 c1 [2] 82 e3 [2] 84 d6 [2] aa d6 [2] 95 ca }

  condition:
    any of them
}