rule TTP_XOR_WriteProcessMemory_e4ce {
  strings:
    $key_e4ce = { b3 bc [2] 81 9e [2] 87 ab [2] a9 ab [2] 96 b7 }

  condition:
    any of them
}