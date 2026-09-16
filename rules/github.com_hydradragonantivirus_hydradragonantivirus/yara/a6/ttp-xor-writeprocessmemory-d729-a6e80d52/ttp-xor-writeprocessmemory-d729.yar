rule TTP_XOR_WriteProcessMemory_d729 {
  strings:
    $key_d729 = { 80 5b [2] b2 79 [2] b4 4c [2] 9a 4c [2] a5 50 }

  condition:
    any of them
}