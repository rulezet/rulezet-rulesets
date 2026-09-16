rule TTP_XOR_WriteProcessMemory_d23a {
  strings:
    $key_d23a = { 85 48 [2] b7 6a [2] b1 5f [2] 9f 5f [2] a0 43 }

  condition:
    any of them
}