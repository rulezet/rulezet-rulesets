rule TTP_XOR_WriteProcessMemory_d619 {
  strings:
    $key_d619 = { 81 6b [2] b3 49 [2] b5 7c [2] 9b 7c [2] a4 60 }

  condition:
    any of them
}