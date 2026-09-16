rule TTP_XOR_WriteProcessMemory_cba9 {
  strings:
    $key_cba9 = { 9c db [2] ae f9 [2] a8 cc [2] 86 cc [2] b9 d0 }

  condition:
    any of them
}