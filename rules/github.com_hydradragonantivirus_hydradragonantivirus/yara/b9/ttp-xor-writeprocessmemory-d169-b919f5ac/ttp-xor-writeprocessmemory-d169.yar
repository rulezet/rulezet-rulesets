rule TTP_XOR_WriteProcessMemory_d169 {
  strings:
    $key_d169 = { 86 1b [2] b4 39 [2] b2 0c [2] 9c 0c [2] a3 10 }

  condition:
    any of them
}