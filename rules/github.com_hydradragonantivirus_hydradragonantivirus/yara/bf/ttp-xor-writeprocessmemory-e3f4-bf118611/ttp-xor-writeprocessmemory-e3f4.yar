rule TTP_XOR_WriteProcessMemory_e3f4 {
  strings:
    $key_e3f4 = { b4 86 [2] 86 a4 [2] 80 91 [2] ae 91 [2] 91 8d }

  condition:
    any of them
}