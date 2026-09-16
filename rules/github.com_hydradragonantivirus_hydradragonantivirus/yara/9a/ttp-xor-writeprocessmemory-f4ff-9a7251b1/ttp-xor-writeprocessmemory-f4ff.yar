rule TTP_XOR_WriteProcessMemory_f4ff {
  strings:
    $key_f4ff = { a3 8d [2] 91 af [2] 97 9a [2] b9 9a [2] 86 86 }

  condition:
    any of them
}