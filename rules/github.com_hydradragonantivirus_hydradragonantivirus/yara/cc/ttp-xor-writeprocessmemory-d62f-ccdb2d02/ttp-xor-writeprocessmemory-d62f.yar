rule TTP_XOR_WriteProcessMemory_d62f {
  strings:
    $key_d62f = { 81 5d [2] b3 7f [2] b5 4a [2] 9b 4a [2] a4 56 }

  condition:
    any of them
}