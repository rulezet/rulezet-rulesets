rule TTP_XOR_WriteProcessMemory_e41c {
  strings:
    $key_e41c = { b3 6e [2] 81 4c [2] 87 79 [2] a9 79 [2] 96 65 }

  condition:
    any of them
}