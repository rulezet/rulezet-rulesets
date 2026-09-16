rule TTP_XOR_WriteProcessMemory_d238 {
  strings:
    $key_d238 = { 85 4a [2] b7 68 [2] b1 5d [2] 9f 5d [2] a0 41 }

  condition:
    any of them
}