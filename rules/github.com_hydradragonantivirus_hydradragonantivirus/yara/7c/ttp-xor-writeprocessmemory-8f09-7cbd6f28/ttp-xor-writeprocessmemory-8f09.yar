rule TTP_XOR_WriteProcessMemory_8f09 {
  strings:
    $key_8f09 = { d8 7b [2] ea 59 [2] ec 6c [2] c2 6c [2] fd 70 }

  condition:
    any of them
}