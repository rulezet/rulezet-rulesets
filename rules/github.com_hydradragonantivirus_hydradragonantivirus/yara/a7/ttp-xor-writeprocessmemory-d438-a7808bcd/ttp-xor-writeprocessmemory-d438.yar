rule TTP_XOR_WriteProcessMemory_d438 {
  strings:
    $key_d438 = { 83 4a [2] b1 68 [2] b7 5d [2] 99 5d [2] a6 41 }

  condition:
    any of them
}