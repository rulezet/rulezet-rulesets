rule TTP_XOR_WriteProcessMemory_e3f1 {
  strings:
    $key_e3f1 = { b4 83 [2] 86 a1 [2] 80 94 [2] ae 94 [2] 91 88 }

  condition:
    any of them
}