rule TTP_XOR_WriteProcessMemory_a188 {
  strings:
    $key_a188 = { f6 fa [2] c4 d8 [2] c2 ed [2] ec ed [2] d3 f1 }

  condition:
    any of them
}