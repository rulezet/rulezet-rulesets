rule TTP_XOR_WriteProcessMemory_d728 {
  strings:
    $key_d728 = { 80 5a [2] b2 78 [2] b4 4d [2] 9a 4d [2] a5 51 }

  condition:
    any of them
}