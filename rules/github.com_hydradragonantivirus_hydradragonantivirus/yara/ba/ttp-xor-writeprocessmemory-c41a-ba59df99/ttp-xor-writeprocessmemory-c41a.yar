rule TTP_XOR_WriteProcessMemory_c41a {
  strings:
    $key_c41a = { 93 68 [2] a1 4a [2] a7 7f [2] 89 7f [2] b6 63 }

  condition:
    any of them
}