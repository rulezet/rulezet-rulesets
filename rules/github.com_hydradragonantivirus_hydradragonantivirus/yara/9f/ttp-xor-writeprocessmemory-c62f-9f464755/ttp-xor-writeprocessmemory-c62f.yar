rule TTP_XOR_WriteProcessMemory_c62f {
  strings:
    $key_c62f = { 91 5d [2] a3 7f [2] a5 4a [2] 8b 4a [2] b4 56 }

  condition:
    any of them
}