rule TTP_XOR_WriteProcessMemory_898a {
  strings:
    $key_898a = { de f8 [2] ec da [2] ea ef [2] c4 ef [2] fb f3 }

  condition:
    any of them
}