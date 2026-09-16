rule TTP_XOR_WriteProcessMemory_8f11 {
  strings:
    $key_8f11 = { d8 63 [2] ea 41 [2] ec 74 [2] c2 74 [2] fd 68 }

  condition:
    any of them
}