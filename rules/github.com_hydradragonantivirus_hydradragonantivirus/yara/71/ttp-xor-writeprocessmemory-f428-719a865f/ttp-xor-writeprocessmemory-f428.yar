rule TTP_XOR_WriteProcessMemory_f428 {
  strings:
    $key_f428 = { a3 5a [2] 91 78 [2] 97 4d [2] b9 4d [2] 86 51 }

  condition:
    any of them
}