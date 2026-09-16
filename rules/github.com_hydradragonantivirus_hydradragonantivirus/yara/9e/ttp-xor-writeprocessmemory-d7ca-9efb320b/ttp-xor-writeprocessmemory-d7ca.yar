rule TTP_XOR_WriteProcessMemory_d7ca {
  strings:
    $key_d7ca = { 80 b8 [2] b2 9a [2] b4 af [2] 9a af [2] a5 b3 }

  condition:
    any of them
}