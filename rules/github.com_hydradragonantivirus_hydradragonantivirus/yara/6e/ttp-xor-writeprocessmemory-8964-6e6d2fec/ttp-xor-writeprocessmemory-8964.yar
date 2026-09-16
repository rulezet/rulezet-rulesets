rule TTP_XOR_WriteProcessMemory_8964 {
  strings:
    $key_8964 = { de 16 [2] ec 34 [2] ea 01 [2] c4 01 [2] fb 1d }

  condition:
    any of them
}