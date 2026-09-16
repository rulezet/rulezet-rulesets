rule TTP_XOR_WriteProcessMemory_8944 {
  strings:
    $key_8944 = { de 36 [2] ec 14 [2] ea 21 [2] c4 21 [2] fb 3d }

  condition:
    any of them
}