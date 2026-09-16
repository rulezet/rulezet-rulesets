rule TTP_XOR_WriteProcessMemory_d614 {
  strings:
    $key_d614 = { 81 66 [2] b3 44 [2] b5 71 [2] 9b 71 [2] a4 6d }

  condition:
    any of them
}