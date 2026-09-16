rule TTP_XOR_WriteProcessMemory_8fc3 {
  strings:
    $key_8fc3 = { d8 b1 [2] ea 93 [2] ec a6 [2] c2 a6 [2] fd ba }

  condition:
    any of them
}