rule TTP_XOR_WriteProcessMemory_c67f {
  strings:
    $key_c67f = { 91 0d [2] a3 2f [2] a5 1a [2] 8b 1a [2] b4 06 }

  condition:
    any of them
}