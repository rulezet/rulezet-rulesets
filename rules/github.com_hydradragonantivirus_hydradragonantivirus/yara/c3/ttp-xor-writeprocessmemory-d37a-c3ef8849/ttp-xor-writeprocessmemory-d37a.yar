rule TTP_XOR_WriteProcessMemory_d37a {
  strings:
    $key_d37a = { 84 08 [2] b6 2a [2] b0 1f [2] 9e 1f [2] a1 03 }

  condition:
    any of them
}