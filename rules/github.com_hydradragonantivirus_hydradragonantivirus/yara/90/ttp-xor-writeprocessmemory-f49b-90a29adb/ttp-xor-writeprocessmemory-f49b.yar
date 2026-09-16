rule TTP_XOR_WriteProcessMemory_f49b {
  strings:
    $key_f49b = { a3 e9 [2] 91 cb [2] 97 fe [2] b9 fe [2] 86 e2 }

  condition:
    any of them
}