rule TTP_XOR_WriteProcessMemory_32f4 {
  strings:
    $key_32f4 = { 65 86 [2] 57 a4 [2] 51 91 [2] 7f 91 [2] 40 8d }

  condition:
    any of them
}