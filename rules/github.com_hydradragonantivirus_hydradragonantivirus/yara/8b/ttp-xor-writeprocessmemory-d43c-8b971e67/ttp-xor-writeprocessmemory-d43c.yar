rule TTP_XOR_WriteProcessMemory_d43c {
  strings:
    $key_d43c = { 83 4e [2] b1 6c [2] b7 59 [2] 99 59 [2] a6 45 }

  condition:
    any of them
}