rule TTP_XOR_WriteProcessMemory_c464 {
  strings:
    $key_c464 = { 93 16 [2] a1 34 [2] a7 01 [2] 89 01 [2] b6 1d }

  condition:
    any of them
}