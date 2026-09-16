rule TTP_XOR_WriteProcessMemory_c6ca {
  strings:
    $key_c6ca = { 91 b8 [2] a3 9a [2] a5 af [2] 8b af [2] b4 b3 }

  condition:
    any of them
}