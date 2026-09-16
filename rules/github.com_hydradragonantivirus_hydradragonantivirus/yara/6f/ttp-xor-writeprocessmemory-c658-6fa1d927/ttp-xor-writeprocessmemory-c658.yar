rule TTP_XOR_WriteProcessMemory_c658 {
  strings:
    $key_c658 = { 91 2a [2] a3 08 [2] a5 3d [2] 8b 3d [2] b4 21 }

  condition:
    any of them
}