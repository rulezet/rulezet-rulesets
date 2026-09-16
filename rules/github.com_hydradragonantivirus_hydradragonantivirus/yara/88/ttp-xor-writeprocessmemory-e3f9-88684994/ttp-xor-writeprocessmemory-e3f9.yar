rule TTP_XOR_WriteProcessMemory_e3f9 {
  strings:
    $key_e3f9 = { b4 8b [2] 86 a9 [2] 80 9c [2] ae 9c [2] 91 80 }

  condition:
    any of them
}