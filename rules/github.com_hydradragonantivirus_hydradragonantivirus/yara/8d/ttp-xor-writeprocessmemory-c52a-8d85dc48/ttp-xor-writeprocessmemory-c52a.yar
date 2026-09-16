rule TTP_XOR_WriteProcessMemory_c52a {
  strings:
    $key_c52a = { 92 58 [2] a0 7a [2] a6 4f [2] 88 4f [2] b7 53 }

  condition:
    any of them
}