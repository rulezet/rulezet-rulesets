rule TTP_XOR_WriteProcessMemory_f98c {
  strings:
    $key_f98c = { ae fe [2] 9c dc [2] 9a e9 [2] b4 e9 [2] 8b f5 }

  condition:
    any of them
}