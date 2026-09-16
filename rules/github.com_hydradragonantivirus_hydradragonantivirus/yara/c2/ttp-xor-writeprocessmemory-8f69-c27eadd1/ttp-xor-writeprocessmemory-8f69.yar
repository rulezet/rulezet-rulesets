rule TTP_XOR_WriteProcessMemory_8f69 {
  strings:
    $key_8f69 = { d8 1b [2] ea 39 [2] ec 0c [2] c2 0c [2] fd 10 }

  condition:
    any of them
}