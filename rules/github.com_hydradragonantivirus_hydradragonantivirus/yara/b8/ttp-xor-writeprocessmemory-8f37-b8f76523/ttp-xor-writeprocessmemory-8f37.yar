rule TTP_XOR_WriteProcessMemory_8f37 {
  strings:
    $key_8f37 = { d8 45 [2] ea 67 [2] ec 52 [2] c2 52 [2] fd 4e }

  condition:
    any of them
}