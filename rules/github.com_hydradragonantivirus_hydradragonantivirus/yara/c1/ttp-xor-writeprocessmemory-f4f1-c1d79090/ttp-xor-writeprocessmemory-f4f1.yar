rule TTP_XOR_WriteProcessMemory_f4f1 {
  strings:
    $key_f4f1 = { a3 83 [2] 91 a1 [2] 97 94 [2] b9 94 [2] 86 88 }

  condition:
    any of them
}