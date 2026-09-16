rule TTP_XOR_WriteProcessMemory_c09c {
  strings:
    $key_c09c = { 97 ee [2] a5 cc [2] a3 f9 [2] 8d f9 [2] b2 e5 }

  condition:
    any of them
}