rule TTP_XOR_WriteProcessMemory_d57a {
  strings:
    $key_d57a = { 82 08 [2] b0 2a [2] b6 1f [2] 98 1f [2] a7 03 }

  condition:
    any of them
}