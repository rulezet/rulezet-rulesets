rule TTP_XOR_WriteProcessMemory_f41b {
  strings:
    $key_f41b = { a3 69 [2] 91 4b [2] 97 7e [2] b9 7e [2] 86 62 }

  condition:
    any of them
}