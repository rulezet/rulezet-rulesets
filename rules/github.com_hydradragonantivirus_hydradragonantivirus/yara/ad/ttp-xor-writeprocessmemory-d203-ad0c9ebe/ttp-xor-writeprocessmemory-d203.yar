rule TTP_XOR_WriteProcessMemory_d203 {
  strings:
    $key_d203 = { 85 71 [2] b7 53 [2] b1 66 [2] 9f 66 [2] a0 7a }

  condition:
    any of them
}