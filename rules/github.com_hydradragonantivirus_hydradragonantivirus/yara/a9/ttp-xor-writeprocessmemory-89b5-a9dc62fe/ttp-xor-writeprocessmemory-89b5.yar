rule TTP_XOR_WriteProcessMemory_89b5 {
  strings:
    $key_89b5 = { de c7 [2] ec e5 [2] ea d0 [2] c4 d0 [2] fb cc }

  condition:
    any of them
}