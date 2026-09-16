rule TTP_XOR_WriteProcessMemory_d50d {
  strings:
    $key_d50d = { 82 7f [2] b0 5d [2] b6 68 [2] 98 68 [2] a7 74 }

  condition:
    any of them
}