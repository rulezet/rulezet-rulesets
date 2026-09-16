rule TTP_XOR_WriteProcessMemory_c63f {
  strings:
    $key_c63f = { 91 4d [2] a3 6f [2] a5 5a [2] 8b 5a [2] b4 46 }

  condition:
    any of them
}