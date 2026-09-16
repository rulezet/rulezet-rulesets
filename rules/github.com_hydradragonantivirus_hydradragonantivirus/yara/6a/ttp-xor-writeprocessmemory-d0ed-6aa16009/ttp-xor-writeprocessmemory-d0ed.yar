rule TTP_XOR_WriteProcessMemory_d0ed {
  strings:
    $key_d0ed = { 87 9f [2] b5 bd [2] b3 88 [2] 9d 88 [2] a2 94 }

  condition:
    any of them
}