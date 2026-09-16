rule TTP_XOR_WriteProcessMemory_c70f {
  strings:
    $key_c70f = { 90 7d [2] a2 5f [2] a4 6a [2] 8a 6a [2] b5 76 }

  condition:
    any of them
}