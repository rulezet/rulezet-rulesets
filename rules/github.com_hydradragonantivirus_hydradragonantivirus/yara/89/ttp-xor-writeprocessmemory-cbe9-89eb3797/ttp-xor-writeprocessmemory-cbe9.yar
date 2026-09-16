rule TTP_XOR_WriteProcessMemory_cbe9 {
  strings:
    $key_cbe9 = { 9c 9b [2] ae b9 [2] a8 8c [2] 86 8c [2] b9 90 }

  condition:
    any of them
}