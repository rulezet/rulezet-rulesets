rule TTP_XOR_WriteProcessMemory_8966 {
  strings:
    $key_8966 = { de 14 [2] ec 36 [2] ea 03 [2] c4 03 [2] fb 1f }

  condition:
    any of them
}