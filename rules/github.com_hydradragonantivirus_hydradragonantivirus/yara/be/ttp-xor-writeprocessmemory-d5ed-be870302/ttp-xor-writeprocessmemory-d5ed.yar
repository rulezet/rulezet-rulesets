rule TTP_XOR_WriteProcessMemory_d5ed {
  strings:
    $key_d5ed = { 82 9f [2] b0 bd [2] b6 88 [2] 98 88 [2] a7 94 }

  condition:
    any of them
}