rule TTP_XOR_WriteProcessMemory_d55d {
  strings:
    $key_d55d = { 82 2f [2] b0 0d [2] b6 38 [2] 98 38 [2] a7 24 }

  condition:
    any of them
}