rule TTP_XOR_WriteProcessMemory_d0eb {
  strings:
    $key_d0eb = { 87 99 [2] b5 bb [2] b3 8e [2] 9d 8e [2] a2 92 }

  condition:
    any of them
}