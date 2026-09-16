rule TTP_XOR_WriteProcessMemory_e3b3 {
  strings:
    $key_e3b3 = { b4 c1 [2] 86 e3 [2] 80 d6 [2] ae d6 [2] 91 ca }

  condition:
    any of them
}