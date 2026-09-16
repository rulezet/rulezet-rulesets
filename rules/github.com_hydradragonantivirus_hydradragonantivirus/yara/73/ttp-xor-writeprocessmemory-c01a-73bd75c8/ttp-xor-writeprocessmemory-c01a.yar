rule TTP_XOR_WriteProcessMemory_c01a {
  strings:
    $key_c01a = { 97 68 [2] a5 4a [2] a3 7f [2] 8d 7f [2] b2 63 }

  condition:
    any of them
}