rule TTP_XOR_WriteProcessMemory_c229 {
  strings:
    $key_c229 = { 95 5b [2] a7 79 [2] a1 4c [2] 8f 4c [2] b0 50 }

  condition:
    any of them
}