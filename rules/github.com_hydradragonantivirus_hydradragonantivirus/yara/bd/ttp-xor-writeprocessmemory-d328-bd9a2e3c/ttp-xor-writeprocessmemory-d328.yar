rule TTP_XOR_WriteProcessMemory_d328 {
  strings:
    $key_d328 = { 84 5a [2] b6 78 [2] b0 4d [2] 9e 4d [2] a1 51 }

  condition:
    any of them
}