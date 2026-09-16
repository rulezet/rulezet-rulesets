rule TTP_XOR_WriteProcessMemory_e3a1 {
  strings:
    $key_e3a1 = { b4 d3 [2] 86 f1 [2] 80 c4 [2] ae c4 [2] 91 d8 }

  condition:
    any of them
}