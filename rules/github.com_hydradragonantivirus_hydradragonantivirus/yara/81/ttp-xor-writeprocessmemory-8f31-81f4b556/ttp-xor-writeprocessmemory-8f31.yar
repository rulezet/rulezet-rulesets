rule TTP_XOR_WriteProcessMemory_8f31 {
  strings:
    $key_8f31 = { d8 43 [2] ea 61 [2] ec 54 [2] c2 54 [2] fd 48 }

  condition:
    any of them
}