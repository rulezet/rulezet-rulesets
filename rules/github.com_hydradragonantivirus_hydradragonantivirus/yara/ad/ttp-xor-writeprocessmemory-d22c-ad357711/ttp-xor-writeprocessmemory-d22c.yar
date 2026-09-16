rule TTP_XOR_WriteProcessMemory_d22c {
  strings:
    $key_d22c = { 85 5e [2] b7 7c [2] b1 49 [2] 9f 49 [2] a0 55 }

  condition:
    any of them
}