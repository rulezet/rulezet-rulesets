rule TTP_XOR_WriteProcessMemory_8f88 {
  strings:
    $key_8f88 = { d8 fa [2] ea d8 [2] ec ed [2] c2 ed [2] fd f1 }

  condition:
    any of them
}