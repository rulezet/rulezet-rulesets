rule TTP_XOR_WriteProcessMemory_c20a {
  strings:
    $key_c20a = { 95 78 [2] a7 5a [2] a1 6f [2] 8f 6f [2] b0 73 }

  condition:
    any of them
}