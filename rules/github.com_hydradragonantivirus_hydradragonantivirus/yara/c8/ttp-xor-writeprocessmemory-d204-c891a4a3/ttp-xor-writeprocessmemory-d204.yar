rule TTP_XOR_WriteProcessMemory_d204 {
  strings:
    $key_d204 = { 85 76 [2] b7 54 [2] b1 61 [2] 9f 61 [2] a0 7d }

  condition:
    any of them
}