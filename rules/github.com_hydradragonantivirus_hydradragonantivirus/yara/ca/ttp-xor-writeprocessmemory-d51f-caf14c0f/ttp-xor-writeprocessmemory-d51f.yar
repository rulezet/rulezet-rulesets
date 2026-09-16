rule TTP_XOR_WriteProcessMemory_d51f {
  strings:
    $key_d51f = { 82 6d [2] b0 4f [2] b6 7a [2] 98 7a [2] a7 66 }

  condition:
    any of them
}