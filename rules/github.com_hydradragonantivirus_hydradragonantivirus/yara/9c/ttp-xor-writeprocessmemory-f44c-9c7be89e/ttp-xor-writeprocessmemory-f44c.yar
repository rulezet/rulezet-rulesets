rule TTP_XOR_WriteProcessMemory_f44c {
  strings:
    $key_f44c = { a3 3e [2] 91 1c [2] 97 29 [2] b9 29 [2] 86 35 }

  condition:
    any of them
}