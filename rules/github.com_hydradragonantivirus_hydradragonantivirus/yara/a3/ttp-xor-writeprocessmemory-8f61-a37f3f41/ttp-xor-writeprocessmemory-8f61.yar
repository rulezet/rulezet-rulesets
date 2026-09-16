rule TTP_XOR_WriteProcessMemory_8f61 {
  strings:
    $key_8f61 = { d8 13 [2] ea 31 [2] ec 04 [2] c2 04 [2] fd 18 }

  condition:
    any of them
}