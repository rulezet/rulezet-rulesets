rule TTP_XOR_WriteProcessMemory_d1ed {
  strings:
    $key_d1ed = { 86 9f [2] b4 bd [2] b2 88 [2] 9c 88 [2] a3 94 }

  condition:
    any of them
}