rule TTP_XOR_WriteProcessMemory_e3e7 {
  strings:
    $key_e3e7 = { b4 95 [2] 86 b7 [2] 80 82 [2] ae 82 [2] 91 9e }

  condition:
    any of them
}