rule TTP_XOR_WriteProcessMemory_c40a {
  strings:
    $key_c40a = { 93 78 [2] a1 5a [2] a7 6f [2] 89 6f [2] b6 73 }

  condition:
    any of them
}