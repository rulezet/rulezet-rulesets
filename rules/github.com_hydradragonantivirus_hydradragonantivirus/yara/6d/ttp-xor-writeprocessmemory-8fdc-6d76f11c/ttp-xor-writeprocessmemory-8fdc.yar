rule TTP_XOR_WriteProcessMemory_8fdc {
  strings:
    $key_8fdc = { d8 ae [2] ea 8c [2] ec b9 [2] c2 b9 [2] fd a5 }

  condition:
    any of them
}