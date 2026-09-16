rule TTP_XOR_WriteProcessMemory_e41e {
  strings:
    $key_e41e = { b3 6c [2] 81 4e [2] 87 7b [2] a9 7b [2] 96 67 }

  condition:
    any of them
}