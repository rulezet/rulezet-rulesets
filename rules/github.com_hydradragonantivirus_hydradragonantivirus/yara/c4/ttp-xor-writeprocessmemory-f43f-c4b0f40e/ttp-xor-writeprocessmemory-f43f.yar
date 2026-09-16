rule TTP_XOR_WriteProcessMemory_f43f {
  strings:
    $key_f43f = { a3 4d [2] 91 6f [2] 97 5a [2] b9 5a [2] 86 46 }

  condition:
    any of them
}