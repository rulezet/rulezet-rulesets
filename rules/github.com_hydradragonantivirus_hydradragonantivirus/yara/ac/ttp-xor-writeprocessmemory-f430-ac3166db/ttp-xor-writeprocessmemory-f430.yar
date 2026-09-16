rule TTP_XOR_WriteProcessMemory_f430 {
  strings:
    $key_f430 = { a3 42 [2] 91 60 [2] 97 55 [2] b9 55 [2] 86 49 }

  condition:
    any of them
}