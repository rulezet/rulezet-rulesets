rule TTP_XOR_WriteProcessMemory_d27a {
  strings:
    $key_d27a = { 85 08 [2] b7 2a [2] b1 1f [2] 9f 1f [2] a0 03 }

  condition:
    any of them
}