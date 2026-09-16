rule TTP_XOR_WriteProcessMemory_d30a {
  strings:
    $key_d30a = { 84 78 [2] b6 5a [2] b0 6f [2] 9e 6f [2] a1 73 }

  condition:
    any of them
}