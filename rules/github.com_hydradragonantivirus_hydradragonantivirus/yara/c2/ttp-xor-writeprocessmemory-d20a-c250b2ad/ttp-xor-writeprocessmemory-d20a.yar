rule TTP_XOR_WriteProcessMemory_d20a {
  strings:
    $key_d20a = { 85 78 [2] b7 5a [2] b1 6f [2] 9f 6f [2] a0 73 }

  condition:
    any of them
}