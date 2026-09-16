rule TTP_XOR_WriteProcessMemory_c73f {
  strings:
    $key_c73f = { 90 4d [2] a2 6f [2] a4 5a [2] 8a 5a [2] b5 46 }

  condition:
    any of them
}