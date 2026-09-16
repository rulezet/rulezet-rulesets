rule TTP_XOR_WriteProcessMemory_8fe8 {
  strings:
    $key_8fe8 = { d8 9a [2] ea b8 [2] ec 8d [2] c2 8d [2] fd 91 }

  condition:
    any of them
}