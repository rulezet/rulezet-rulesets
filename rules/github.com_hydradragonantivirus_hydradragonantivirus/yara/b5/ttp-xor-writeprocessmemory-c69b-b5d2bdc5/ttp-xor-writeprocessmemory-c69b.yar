rule TTP_XOR_WriteProcessMemory_c69b {
  strings:
    $key_c69b = { 91 e9 [2] a3 cb [2] a5 fe [2] 8b fe [2] b4 e2 }

  condition:
    any of them
}