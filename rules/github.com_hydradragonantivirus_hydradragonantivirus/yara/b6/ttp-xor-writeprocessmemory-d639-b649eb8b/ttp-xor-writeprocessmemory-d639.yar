rule TTP_XOR_WriteProcessMemory_d639 {
  strings:
    $key_d639 = { 81 4b [2] b3 69 [2] b5 5c [2] 9b 5c [2] a4 40 }

  condition:
    any of them
}