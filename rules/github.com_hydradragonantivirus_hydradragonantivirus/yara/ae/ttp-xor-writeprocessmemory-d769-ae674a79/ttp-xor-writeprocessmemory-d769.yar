rule TTP_XOR_WriteProcessMemory_d769 {
  strings:
    $key_d769 = { 80 1b [2] b2 39 [2] b4 0c [2] 9a 0c [2] a5 10 }

  condition:
    any of them
}