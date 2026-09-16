rule TTP_XOR_WriteProcessMemory_c769 {
  strings:
    $key_c769 = { 90 1b [2] a2 39 [2] a4 0c [2] 8a 0c [2] b5 10 }

  condition:
    any of them
}