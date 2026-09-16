rule TTP_XOR_WriteProcessMemory_f89b {
  strings:
    $key_f89b = { af e9 [2] 9d cb [2] 9b fe [2] b5 fe [2] 8a e2 }

  condition:
    any of them
}