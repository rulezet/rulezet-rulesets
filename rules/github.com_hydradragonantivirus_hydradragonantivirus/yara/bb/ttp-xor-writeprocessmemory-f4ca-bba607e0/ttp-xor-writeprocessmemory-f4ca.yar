rule TTP_XOR_WriteProcessMemory_f4ca {
  strings:
    $key_f4ca = { a3 b8 [2] 91 9a [2] 97 af [2] b9 af [2] 86 b3 }

  condition:
    any of them
}