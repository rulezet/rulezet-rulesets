rule TTP_XOR_WriteProcessMemory_8930 {
  strings:
    $key_8930 = { de 42 [2] ec 60 [2] ea 55 [2] c4 55 [2] fb 49 }

  condition:
    any of them
}