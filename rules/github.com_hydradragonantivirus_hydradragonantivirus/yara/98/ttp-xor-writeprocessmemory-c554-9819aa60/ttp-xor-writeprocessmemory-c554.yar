rule TTP_XOR_WriteProcessMemory_c554 {
  strings:
    $key_c554 = { 92 26 [2] a0 04 [2] a6 31 [2] 88 31 [2] b7 2d }

  condition:
    any of them
}