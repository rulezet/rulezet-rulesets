rule TTP_XOR_WriteProcessMemory_c10a {
  strings:
    $key_c10a = { 96 78 [2] a4 5a [2] a2 6f [2] 8c 6f [2] b3 73 }

  condition:
    any of them
}