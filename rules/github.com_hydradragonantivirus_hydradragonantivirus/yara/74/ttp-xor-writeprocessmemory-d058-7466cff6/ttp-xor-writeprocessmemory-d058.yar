rule TTP_XOR_WriteProcessMemory_d058 {
  strings:
    $key_d058 = { 87 2a [2] b5 08 [2] b3 3d [2] 9d 3d [2] a2 21 }

  condition:
    any of them
}