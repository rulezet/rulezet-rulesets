rule TTP_XOR_WriteProcessMemory_c37a {
  strings:
    $key_c37a = { 94 08 [2] a6 2a [2] a0 1f [2] 8e 1f [2] b1 03 }

  condition:
    any of them
}