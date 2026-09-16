rule TTP_XOR_WriteProcessMemory_f43b {
  strings:
    $key_f43b = { a3 49 [2] 91 6b [2] 97 5e [2] b9 5e [2] 86 42 }

  condition:
    any of them
}