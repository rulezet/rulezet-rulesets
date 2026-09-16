rule TTP_XOR_WriteProcessMemory_89c0 {
  strings:
    $key_89c0 = { de b2 [2] ec 90 [2] ea a5 [2] c4 a5 [2] fb b9 }

  condition:
    any of them
}