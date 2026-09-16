rule TTP_XOR_WriteProcessMemory_d358 {
  strings:
    $key_d358 = { 84 2a [2] b6 08 [2] b0 3d [2] 9e 3d [2] a1 21 }

  condition:
    any of them
}