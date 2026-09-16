rule TTP_XOR_WriteProcessMemory_f447 {
  strings:
    $key_f447 = { a3 35 [2] 91 17 [2] 97 22 [2] b9 22 [2] 86 3e }

  condition:
    any of them
}