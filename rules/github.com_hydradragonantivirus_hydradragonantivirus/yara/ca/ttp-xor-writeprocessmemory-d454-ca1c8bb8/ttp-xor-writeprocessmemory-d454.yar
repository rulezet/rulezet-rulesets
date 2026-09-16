rule TTP_XOR_WriteProcessMemory_d454 {
  strings:
    $key_d454 = { 83 26 [2] b1 04 [2] b7 31 [2] 99 31 [2] a6 2d }

  condition:
    any of them
}