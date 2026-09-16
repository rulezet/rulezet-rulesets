rule TTP_XOR_WriteProcessMemory_f42f {
  strings:
    $key_f42f = { a3 5d [2] 91 7f [2] 97 4a [2] b9 4a [2] 86 56 }

  condition:
    any of them
}