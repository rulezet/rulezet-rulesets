rule TTP_XOR_WriteProcessMemory_f40f {
  strings:
    $key_f40f = { a3 7d [2] 91 5f [2] 97 6a [2] b9 6a [2] 86 76 }

  condition:
    any of them
}