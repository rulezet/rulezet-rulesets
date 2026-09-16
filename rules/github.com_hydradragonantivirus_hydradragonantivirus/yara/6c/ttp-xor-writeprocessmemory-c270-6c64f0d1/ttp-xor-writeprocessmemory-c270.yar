rule TTP_XOR_WriteProcessMemory_c270 {
  strings:
    $key_c270 = { 95 02 [2] a7 20 [2] a1 15 [2] 8f 15 [2] b0 09 }

  condition:
    any of them
}