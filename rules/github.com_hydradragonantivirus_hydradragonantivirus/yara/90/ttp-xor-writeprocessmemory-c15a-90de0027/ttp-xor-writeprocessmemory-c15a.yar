rule TTP_XOR_WriteProcessMemory_c15a {
  strings:
    $key_c15a = { 96 28 [2] a4 0a [2] a2 3f [2] 8c 3f [2] b3 23 }

  condition:
    any of them
}