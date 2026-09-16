rule TTP_XOR_WriteProcessMemory_d569 {
  strings:
    $key_d569 = { 82 1b [2] b0 39 [2] b6 0c [2] 98 0c [2] a7 10 }

  condition:
    any of them
}