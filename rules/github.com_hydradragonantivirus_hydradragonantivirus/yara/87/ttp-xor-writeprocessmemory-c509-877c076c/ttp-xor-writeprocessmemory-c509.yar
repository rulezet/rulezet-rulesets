rule TTP_XOR_WriteProcessMemory_c509 {
  strings:
    $key_c509 = { 92 7b [2] a0 59 [2] a6 6c [2] 88 6c [2] b7 70 }

  condition:
    any of them
}