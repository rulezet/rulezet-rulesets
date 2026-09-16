rule TTP_XOR_WriteProcessMemory_d31a {
  strings:
    $key_d31a = { 84 68 [2] b6 4a [2] b0 7f [2] 9e 7f [2] a1 63 }

  condition:
    any of them
}