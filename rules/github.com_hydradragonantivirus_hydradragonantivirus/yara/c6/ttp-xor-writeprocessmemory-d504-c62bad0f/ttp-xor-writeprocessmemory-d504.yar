rule TTP_XOR_WriteProcessMemory_d504 {
  strings:
    $key_d504 = { 82 76 [2] b0 54 [2] b6 61 [2] 98 61 [2] a7 7d }

  condition:
    any of them
}