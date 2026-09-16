rule TTP_XOR_WriteProcessMemory_f4d9 {
  strings:
    $key_f4d9 = { a3 ab [2] 91 89 [2] 97 bc [2] b9 bc [2] 86 a0 }

  condition:
    any of them
}