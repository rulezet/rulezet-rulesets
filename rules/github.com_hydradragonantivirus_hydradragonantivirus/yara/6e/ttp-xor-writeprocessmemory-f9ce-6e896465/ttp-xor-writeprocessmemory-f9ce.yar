rule TTP_XOR_WriteProcessMemory_f9ce {
  strings:
    $key_f9ce = { ae bc [2] 9c 9e [2] 9a ab [2] b4 ab [2] 8b b7 }

  condition:
    any of them
}