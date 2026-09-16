rule TTP_XOR_WriteProcessMemory_cbc8 {
  strings:
    $key_cbc8 = { 9c ba [2] ae 98 [2] a8 ad [2] 86 ad [2] b9 b1 }

  condition:
    any of them
}