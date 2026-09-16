rule TTP_XOR_WriteProcessMemory_d459 {
  strings:
    $key_d459 = { 83 2b [2] b1 09 [2] b7 3c [2] 99 3c [2] a6 20 }

  condition:
    any of them
}