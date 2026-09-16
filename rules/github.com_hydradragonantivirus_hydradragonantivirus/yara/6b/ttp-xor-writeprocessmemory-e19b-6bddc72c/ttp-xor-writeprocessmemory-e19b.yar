rule TTP_XOR_WriteProcessMemory_e19b {
  strings:
    $key_e19b = { b6 e9 [2] 84 cb [2] 82 fe [2] ac fe [2] 93 e2 }

  condition:
    any of them
}