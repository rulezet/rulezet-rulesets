rule TTP_XOR_WriteProcessMemory_e312 {
  strings:
    $key_e312 = { b4 60 [2] 86 42 [2] 80 77 [2] ae 77 [2] 91 6b }

  condition:
    any of them
}