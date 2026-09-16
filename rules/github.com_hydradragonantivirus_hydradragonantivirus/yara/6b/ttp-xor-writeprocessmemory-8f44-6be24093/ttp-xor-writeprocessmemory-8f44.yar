rule TTP_XOR_WriteProcessMemory_8f44 {
  strings:
    $key_8f44 = { d8 36 [2] ea 14 [2] ec 21 [2] c2 21 [2] fd 3d }

  condition:
    any of them
}