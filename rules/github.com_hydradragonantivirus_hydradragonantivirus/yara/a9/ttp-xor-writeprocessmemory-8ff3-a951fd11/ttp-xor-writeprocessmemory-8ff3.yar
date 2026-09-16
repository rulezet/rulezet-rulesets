rule TTP_XOR_WriteProcessMemory_8ff3 {
  strings:
    $key_8ff3 = { d8 81 [2] ea a3 [2] ec 96 [2] c2 96 [2] fd 8a }

  condition:
    any of them
}