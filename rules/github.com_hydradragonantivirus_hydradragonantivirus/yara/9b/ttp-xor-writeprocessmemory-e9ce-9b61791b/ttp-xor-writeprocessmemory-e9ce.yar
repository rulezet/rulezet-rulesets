rule TTP_XOR_WriteProcessMemory_e9ce {
  strings:
    $key_e9ce = { be bc [2] 8c 9e [2] 8a ab [2] a4 ab [2] 9b b7 }

  condition:
    any of them
}