rule TTP_XOR_WriteProcessMemory_d433 {
  strings:
    $key_d433 = { 83 41 [2] b1 63 [2] b7 56 [2] 99 56 [2] a6 4a }

  condition:
    any of them
}