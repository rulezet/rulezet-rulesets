rule TTP_XOR_WriteProcessMemory_f42a {
  strings:
    $key_f42a = { a3 58 [2] 91 7a [2] 97 4f [2] b9 4f [2] 86 53 }

  condition:
    any of them
}