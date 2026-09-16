rule TTP_XOR_WriteProcessMemory_8fdd {
  strings:
    $key_8fdd = { d8 af [2] ea 8d [2] ec b8 [2] c2 b8 [2] fd a4 }

  condition:
    any of them
}