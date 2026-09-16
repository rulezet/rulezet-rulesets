rule TTP_XOR_WriteProcessMemory_c028 {
  strings:
    $key_c028 = { 97 5a [2] a5 78 [2] a3 4d [2] 8d 4d [2] b2 51 }

  condition:
    any of them
}