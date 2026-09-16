rule TTP_XOR_WriteProcessMemory_d424 {
  strings:
    $key_d424 = { 83 56 [2] b1 74 [2] b7 41 [2] 99 41 [2] a6 5d }

  condition:
    any of them
}