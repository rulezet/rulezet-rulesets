rule TTP_XOR_WriteProcessMemory_c540 {
  strings:
    $key_c540 = { 92 32 [2] a0 10 [2] a6 25 [2] 88 25 [2] b7 39 }

  condition:
    any of them
}