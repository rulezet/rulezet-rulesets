rule TTP_XOR_WriteProcessMemory_f2bd {
  strings:
    $key_f2bd = { a5 cf [2] 97 ed [2] 91 d8 [2] bf d8 [2] 80 c4 }

  condition:
    any of them
}