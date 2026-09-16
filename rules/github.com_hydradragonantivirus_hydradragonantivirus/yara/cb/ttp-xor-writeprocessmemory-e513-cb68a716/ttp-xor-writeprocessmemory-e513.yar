rule TTP_XOR_WriteProcessMemory_e513 {
  strings:
    $key_e513 = { b2 61 [2] 80 43 [2] 86 76 [2] a8 76 [2] 97 6a }

  condition:
    any of them
}