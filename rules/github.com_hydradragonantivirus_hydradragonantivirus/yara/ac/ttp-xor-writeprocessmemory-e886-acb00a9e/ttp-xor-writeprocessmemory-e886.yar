rule TTP_XOR_WriteProcessMemory_e886 {
  strings:
    $key_e886 = { bf f4 [2] 8d d6 [2] 8b e3 [2] a5 e3 [2] 9a ff }

  condition:
    any of them
}