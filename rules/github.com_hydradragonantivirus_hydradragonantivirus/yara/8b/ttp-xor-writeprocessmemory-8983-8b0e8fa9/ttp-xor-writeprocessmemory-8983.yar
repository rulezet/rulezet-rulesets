rule TTP_XOR_WriteProcessMemory_8983 {
  strings:
    $key_8983 = { de f1 [2] ec d3 [2] ea e6 [2] c4 e6 [2] fb fa }

  condition:
    any of them
}