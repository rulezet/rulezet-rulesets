rule TTP_XOR_WriteProcessMemory_c7ca {
  strings:
    $key_c7ca = { 90 b8 [2] a2 9a [2] a4 af [2] 8a af [2] b5 b3 }

  condition:
    any of them
}