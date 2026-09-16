rule TTP_XOR_WriteProcessMemory_d45a {
  strings:
    $key_d45a = { 83 28 [2] b1 0a [2] b7 3f [2] 99 3f [2] a6 23 }

  condition:
    any of them
}