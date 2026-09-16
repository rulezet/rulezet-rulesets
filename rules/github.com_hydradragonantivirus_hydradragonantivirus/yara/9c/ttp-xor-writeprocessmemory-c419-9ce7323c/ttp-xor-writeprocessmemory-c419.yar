rule TTP_XOR_WriteProcessMemory_c419 {
  strings:
    $key_c419 = { 93 6b [2] a1 49 [2] a7 7c [2] 89 7c [2] b6 60 }

  condition:
    any of them
}