rule TTP_XOR_WriteProcessMemory_c77a {
  strings:
    $key_c77a = { 90 08 [2] a2 2a [2] a4 1f [2] 8a 1f [2] b5 03 }

  condition:
    any of them
}