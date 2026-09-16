rule TTP_XOR_WriteProcessMemory_d45d {
  strings:
    $key_d45d = { 83 2f [2] b1 0d [2] b7 38 [2] 99 38 [2] a6 24 }

  condition:
    any of them
}