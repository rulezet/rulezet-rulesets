rule TTP_XOR_WriteProcessMemory_8f34 {
  strings:
    $key_8f34 = { d8 46 [2] ea 64 [2] ec 51 [2] c2 51 [2] fd 4d }

  condition:
    any of them
}