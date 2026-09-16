rule TTP_XOR_WriteProcessMemory_8934 {
  strings:
    $key_8934 = { de 46 [2] ec 64 [2] ea 51 [2] c4 51 [2] fb 4d }

  condition:
    any of them
}