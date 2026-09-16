rule TTP_XOR_WriteProcessMemory_c00f {
  strings:
    $key_c00f = { 97 7d [2] a5 5f [2] a3 6a [2] 8d 6a [2] b2 76 }

  condition:
    any of them
}