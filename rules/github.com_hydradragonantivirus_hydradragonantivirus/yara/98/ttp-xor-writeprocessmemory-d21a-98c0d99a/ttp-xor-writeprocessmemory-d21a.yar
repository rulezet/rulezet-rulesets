rule TTP_XOR_WriteProcessMemory_d21a {
  strings:
    $key_d21a = { 85 68 [2] b7 4a [2] b1 7f [2] 9f 7f [2] a0 63 }

  condition:
    any of them
}