rule TTP_XOR_WriteProcessMemory_f948 {
  strings:
    $key_f948 = { ae 3a [2] 9c 18 [2] 9a 2d [2] b4 2d [2] 8b 31 }

  condition:
    any of them
}