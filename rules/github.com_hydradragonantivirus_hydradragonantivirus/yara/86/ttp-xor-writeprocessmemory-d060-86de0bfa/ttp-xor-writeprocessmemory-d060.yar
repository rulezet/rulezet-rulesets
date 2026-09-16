rule TTP_XOR_WriteProcessMemory_d060 {
  strings:
    $key_d060 = { 87 12 [2] b5 30 [2] b3 05 [2] 9d 05 [2] a2 19 }

  condition:
    any of them
}