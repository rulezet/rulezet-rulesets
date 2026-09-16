rule TTP_XOR_WriteProcessMemory_f4fc {
  strings:
    $key_f4fc = { a3 8e [2] 91 ac [2] 97 99 [2] b9 99 [2] 86 85 }

  condition:
    any of them
}