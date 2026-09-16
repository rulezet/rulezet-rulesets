rule TTP_XOR_WriteProcessMemory_c3d8 {
  strings:
    $key_c3d8 = { 94 aa [2] a6 88 [2] a0 bd [2] 8e bd [2] b1 a1 }

  condition:
    any of them
}