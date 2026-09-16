rule TTP_XOR_WriteProcessMemory_c66f {
  strings:
    $key_c66f = { 91 1d [2] a3 3f [2] a5 0a [2] 8b 0a [2] b4 16 }

  condition:
    any of them
}