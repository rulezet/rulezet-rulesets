rule TTP_XOR_WriteProcessMemory_f41c {
  strings:
    $key_f41c = { a3 6e [2] 91 4c [2] 97 79 [2] b9 79 [2] 86 65 }

  condition:
    any of them
}