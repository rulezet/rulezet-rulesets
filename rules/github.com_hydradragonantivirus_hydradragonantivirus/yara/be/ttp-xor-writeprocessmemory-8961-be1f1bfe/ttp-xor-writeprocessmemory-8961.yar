rule TTP_XOR_WriteProcessMemory_8961 {
  strings:
    $key_8961 = { de 13 [2] ec 31 [2] ea 04 [2] c4 04 [2] fb 18 }

  condition:
    any of them
}