rule TTP_XOR_WriteProcessMemory_d56f {
  strings:
    $key_d56f = { 82 1d [2] b0 3f [2] b6 0a [2] 98 0a [2] a7 16 }

  condition:
    any of them
}