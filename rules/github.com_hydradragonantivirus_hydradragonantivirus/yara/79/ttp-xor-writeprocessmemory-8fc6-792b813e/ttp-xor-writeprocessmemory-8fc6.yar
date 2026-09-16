rule TTP_XOR_WriteProcessMemory_8fc6 {
  strings:
    $key_8fc6 = { d8 b4 [2] ea 96 [2] ec a3 [2] c2 a3 [2] fd bf }

  condition:
    any of them
}