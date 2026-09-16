rule TTP_XOR_WriteProcessMemory_c23a {
  strings:
    $key_c23a = { 95 48 [2] a7 6a [2] a1 5f [2] 8f 5f [2] b0 43 }

  condition:
    any of them
}