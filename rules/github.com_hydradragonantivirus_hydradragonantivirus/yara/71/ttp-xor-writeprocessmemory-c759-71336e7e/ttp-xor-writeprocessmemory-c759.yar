rule TTP_XOR_WriteProcessMemory_c759 {
  strings:
    $key_c759 = { 90 2b [2] a2 09 [2] a4 3c [2] 8a 3c [2] b5 20 }

  condition:
    any of them
}