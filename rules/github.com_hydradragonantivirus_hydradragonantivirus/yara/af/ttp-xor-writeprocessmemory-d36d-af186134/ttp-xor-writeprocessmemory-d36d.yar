rule TTP_XOR_WriteProcessMemory_d36d {
  strings:
    $key_d36d = { 84 1f [2] b6 3d [2] b0 08 [2] 9e 08 [2] a1 14 }

  condition:
    any of them
}