rule TTP_XOR_WriteProcessMemory_d128 {
  strings:
    $key_d128 = { 86 5a [2] b4 78 [2] b2 4d [2] 9c 4d [2] a3 51 }

  condition:
    any of them
}