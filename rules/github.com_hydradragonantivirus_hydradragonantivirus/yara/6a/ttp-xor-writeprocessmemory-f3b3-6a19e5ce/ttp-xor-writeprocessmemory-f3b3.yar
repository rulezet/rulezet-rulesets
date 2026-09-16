rule TTP_XOR_WriteProcessMemory_f3b3 {
  strings:
    $key_f3b3 = { a4 c1 [2] 96 e3 [2] 90 d6 [2] be d6 [2] 81 ca }

  condition:
    any of them
}