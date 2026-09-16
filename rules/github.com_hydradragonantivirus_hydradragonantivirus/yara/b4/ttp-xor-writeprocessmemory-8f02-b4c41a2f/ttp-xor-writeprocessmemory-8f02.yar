rule TTP_XOR_WriteProcessMemory_8f02 {
  strings:
    $key_8f02 = { d8 70 [2] ea 52 [2] ec 67 [2] c2 67 [2] fd 7b }

  condition:
    any of them
}