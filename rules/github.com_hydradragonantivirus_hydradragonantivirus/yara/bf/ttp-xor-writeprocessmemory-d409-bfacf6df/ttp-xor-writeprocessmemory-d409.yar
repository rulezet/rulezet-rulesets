rule TTP_XOR_WriteProcessMemory_d409 {
  strings:
    $key_d409 = { 83 7b [2] b1 59 [2] b7 6c [2] 99 6c [2] a6 70 }

  condition:
    any of them
}