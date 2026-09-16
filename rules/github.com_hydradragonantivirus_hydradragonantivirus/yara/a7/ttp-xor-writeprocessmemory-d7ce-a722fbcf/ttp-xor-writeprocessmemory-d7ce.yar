rule TTP_XOR_WriteProcessMemory_d7ce {
  strings:
    $key_d7ce = { 80 bc [2] b2 9e [2] b4 ab [2] 9a ab [2] a5 b7 }

  condition:
    any of them
}