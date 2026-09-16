rule TTP_XOR_WriteProcessMemory_8f2c {
  strings:
    $key_8f2c = { d8 5e [2] ea 7c [2] ec 49 [2] c2 49 [2] fd 55 }

  condition:
    any of them
}