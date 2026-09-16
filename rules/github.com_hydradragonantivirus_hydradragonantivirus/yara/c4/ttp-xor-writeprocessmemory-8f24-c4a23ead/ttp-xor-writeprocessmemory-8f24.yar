rule TTP_XOR_WriteProcessMemory_8f24 {
  strings:
    $key_8f24 = { d8 56 [2] ea 74 [2] ec 41 [2] c2 41 [2] fd 5d }

  condition:
    any of them
}