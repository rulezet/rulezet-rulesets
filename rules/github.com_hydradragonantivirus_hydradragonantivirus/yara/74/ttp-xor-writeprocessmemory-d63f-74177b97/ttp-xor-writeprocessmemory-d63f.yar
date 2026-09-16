rule TTP_XOR_WriteProcessMemory_d63f {
  strings:
    $key_d63f = { 81 4d [2] b3 6f [2] b5 5a [2] 9b 5a [2] a4 46 }

  condition:
    any of them
}