rule TTP_XOR_WriteProcessMemory_c53a {
  strings:
    $key_c53a = { 92 48 [2] a0 6a [2] a6 5f [2] 88 5f [2] b7 43 }

  condition:
    any of them
}