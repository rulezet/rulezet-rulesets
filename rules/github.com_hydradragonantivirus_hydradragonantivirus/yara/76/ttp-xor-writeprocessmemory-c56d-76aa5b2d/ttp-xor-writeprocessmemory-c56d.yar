rule TTP_XOR_WriteProcessMemory_c56d {
  strings:
    $key_c56d = { 92 1f [2] a0 3d [2] a6 08 [2] 88 08 [2] b7 14 }

  condition:
    any of them
}