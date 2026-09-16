rule TTP_XOR_WriteProcessMemory_f4ec {
  strings:
    $key_f4ec = { a3 9e [2] 91 bc [2] 97 89 [2] b9 89 [2] 86 95 }

  condition:
    any of them
}