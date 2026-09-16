rule TTP_XOR_WriteProcessMemory_d528 {
  strings:
    $key_d528 = { 82 5a [2] b0 78 [2] b6 4d [2] 98 4d [2] a7 51 }

  condition:
    any of them
}