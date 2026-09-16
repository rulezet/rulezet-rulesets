rule TTP_XOR_WriteProcessMemory_d46a {
  strings:
    $key_d46a = { 83 18 [2] b1 3a [2] b7 0f [2] 99 0f [2] a6 13 }

  condition:
    any of them
}