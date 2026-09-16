rule TTP_XOR_WriteProcessMemory_e41f {
  strings:
    $key_e41f = { b3 6d [2] 81 4f [2] 87 7a [2] a9 7a [2] 96 66 }

  condition:
    any of them
}