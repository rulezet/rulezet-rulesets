rule TTP_XOR_WriteProcessMemory_d55a {
  strings:
    $key_d55a = { 82 28 [2] b0 0a [2] b6 3f [2] 98 3f [2] a7 23 }

  condition:
    any of them
}