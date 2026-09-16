rule TTP_XOR_WriteProcessMemory_8f13 {
  strings:
    $key_8f13 = { d8 61 [2] ea 43 [2] ec 76 [2] c2 76 [2] fd 6a }

  condition:
    any of them
}