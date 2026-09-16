rule TTP_XOR_WriteProcessMemory_89ec {
  strings:
    $key_89ec = { de 9e [2] ec bc [2] ea 89 [2] c4 89 [2] fb 95 }

  condition:
    any of them
}