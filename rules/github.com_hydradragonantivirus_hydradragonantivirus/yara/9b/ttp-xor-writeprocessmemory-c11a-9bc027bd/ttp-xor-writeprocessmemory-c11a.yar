rule TTP_XOR_WriteProcessMemory_c11a {
  strings:
    $key_c11a = { 96 68 [2] a4 4a [2] a2 7f [2] 8c 7f [2] b3 63 }

  condition:
    any of them
}