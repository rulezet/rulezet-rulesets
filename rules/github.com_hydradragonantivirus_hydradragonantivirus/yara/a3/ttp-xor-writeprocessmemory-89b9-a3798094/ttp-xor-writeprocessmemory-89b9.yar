rule TTP_XOR_WriteProcessMemory_89b9 {
  strings:
    $key_89b9 = { de cb [2] ec e9 [2] ea dc [2] c4 dc [2] fb c0 }

  condition:
    any of them
}