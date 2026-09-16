rule TTP_XOR_WriteProcessMemory_d23e {
  strings:
    $key_d23e = { 85 4c [2] b7 6e [2] b1 5b [2] 9f 5b [2] a0 47 }

  condition:
    any of them
}