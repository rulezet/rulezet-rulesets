rule TTP_XOR_WriteProcessMemory_8f49 {
  strings:
    $key_8f49 = { d8 3b [2] ea 19 [2] ec 2c [2] c2 2c [2] fd 30 }

  condition:
    any of them
}