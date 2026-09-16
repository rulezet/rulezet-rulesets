rule TTP_XOR_WriteProcessMemory_d07f {
  strings:
    $key_d07f = { 87 0d [2] b5 2f [2] b3 1a [2] 9d 1a [2] a2 06 }

  condition:
    any of them
}