rule TTP_XOR_WriteProcessMemory_d418 {
  strings:
    $key_d418 = { 83 6a [2] b1 48 [2] b7 7d [2] 99 7d [2] a6 61 }

  condition:
    any of them
}