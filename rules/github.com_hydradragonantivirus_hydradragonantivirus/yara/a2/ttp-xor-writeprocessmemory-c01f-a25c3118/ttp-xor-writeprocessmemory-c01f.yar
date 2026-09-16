rule TTP_XOR_WriteProcessMemory_c01f {
  strings:
    $key_c01f = { 97 6d [2] a5 4f [2] a3 7a [2] 8d 7a [2] b2 66 }

  condition:
    any of them
}