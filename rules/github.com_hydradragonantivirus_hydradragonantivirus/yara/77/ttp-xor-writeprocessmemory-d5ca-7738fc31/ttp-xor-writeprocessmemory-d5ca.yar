rule TTP_XOR_WriteProcessMemory_d5ca {
  strings:
    $key_d5ca = { 82 b8 [2] b0 9a [2] b6 af [2] 98 af [2] a7 b3 }

  condition:
    any of them
}