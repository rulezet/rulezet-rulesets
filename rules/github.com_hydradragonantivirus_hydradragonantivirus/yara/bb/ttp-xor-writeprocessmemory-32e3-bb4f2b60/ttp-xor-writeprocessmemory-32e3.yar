rule TTP_XOR_WriteProcessMemory_32e3 {
  strings:
    $key_32e3 = { 65 91 [2] 57 b3 [2] 51 86 [2] 7f 86 [2] 40 9a }

  condition:
    any of them
}