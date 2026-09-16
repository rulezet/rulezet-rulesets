rule TTP_XOR_WriteProcessMemory_c539 {
  strings:
    $key_c539 = { 92 4b [2] a0 69 [2] a6 5c [2] 88 5c [2] b7 40 }

  condition:
    any of them
}