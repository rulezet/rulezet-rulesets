rule TTP_XOR_WriteProcessMemory_c009 {
  strings:
    $key_c009 = { 97 7b [2] a5 59 [2] a3 6c [2] 8d 6c [2] b2 70 }

  condition:
    any of them
}