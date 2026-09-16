rule TTP_XOR_WriteProcessMemory_d60a {
  strings:
    $key_d60a = { 81 78 [2] b3 5a [2] b5 6f [2] 9b 6f [2] a4 73 }

  condition:
    any of them
}