rule TTP_XOR_WriteProcessMemory_c5ca {
  strings:
    $key_c5ca = { 92 b8 [2] a0 9a [2] a6 af [2] 88 af [2] b7 b3 }

  condition:
    any of them
}