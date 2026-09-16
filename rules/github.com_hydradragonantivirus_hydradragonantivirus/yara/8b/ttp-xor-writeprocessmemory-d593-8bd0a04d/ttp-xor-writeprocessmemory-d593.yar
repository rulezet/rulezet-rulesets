rule TTP_XOR_WriteProcessMemory_d593 {
  strings:
    $key_d593 = { 82 e1 [2] b0 c3 [2] b6 f6 [2] 98 f6 [2] a7 ea }

  condition:
    any of them
}