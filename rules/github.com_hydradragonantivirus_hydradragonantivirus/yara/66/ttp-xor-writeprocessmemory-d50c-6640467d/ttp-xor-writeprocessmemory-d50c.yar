rule TTP_XOR_WriteProcessMemory_d50c {
  strings:
    $key_d50c = { 82 7e [2] b0 5c [2] b6 69 [2] 98 69 [2] a7 75 }

  condition:
    any of them
}