rule TTP_XOR_WriteProcessMemory_c78d {
  strings:
    $key_c78d = { 90 ff [2] a2 dd [2] a4 e8 [2] 8a e8 [2] b5 f4 }

  condition:
    any of them
}