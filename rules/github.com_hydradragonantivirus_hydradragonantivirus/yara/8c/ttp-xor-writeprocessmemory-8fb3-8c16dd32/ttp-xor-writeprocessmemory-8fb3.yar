rule TTP_XOR_WriteProcessMemory_8fb3 {
  strings:
    $key_8fb3 = { d8 c1 [2] ea e3 [2] ec d6 [2] c2 d6 [2] fd ca }

  condition:
    any of them
}