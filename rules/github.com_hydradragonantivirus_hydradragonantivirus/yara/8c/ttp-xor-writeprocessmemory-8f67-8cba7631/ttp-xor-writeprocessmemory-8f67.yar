rule TTP_XOR_WriteProcessMemory_8f67 {
  strings:
    $key_8f67 = { d8 15 [2] ea 37 [2] ec 02 [2] c2 02 [2] fd 1e }

  condition:
    any of them
}