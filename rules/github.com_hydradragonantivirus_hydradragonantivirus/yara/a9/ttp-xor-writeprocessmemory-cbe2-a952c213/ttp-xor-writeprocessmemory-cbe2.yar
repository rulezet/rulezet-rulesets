rule TTP_XOR_WriteProcessMemory_cbe2 {
  strings:
    $key_cbe2 = { 9c 90 [2] ae b2 [2] a8 87 [2] 86 87 [2] b9 9b }

  condition:
    any of them
}