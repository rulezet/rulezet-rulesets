rule TTP_XOR_WriteProcessMemory_8905 {
  strings:
    $key_8905 = { de 77 [2] ec 55 [2] ea 60 [2] c4 60 [2] fb 7c }

  condition:
    any of them
}