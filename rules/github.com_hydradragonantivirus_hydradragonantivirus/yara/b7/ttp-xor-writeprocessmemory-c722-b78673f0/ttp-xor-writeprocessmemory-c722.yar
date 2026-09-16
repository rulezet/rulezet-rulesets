rule TTP_XOR_WriteProcessMemory_c722 {
  strings:
    $key_c722 = { 90 50 [2] a2 72 [2] a4 47 [2] 8a 47 [2] b5 5b }

  condition:
    any of them
}