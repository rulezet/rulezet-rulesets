rule TTP_XOR_WriteProcessMemory_8f14 {
  strings:
    $key_8f14 = { d8 66 [2] ea 44 [2] ec 71 [2] c2 71 [2] fd 6d }

  condition:
    any of them
}