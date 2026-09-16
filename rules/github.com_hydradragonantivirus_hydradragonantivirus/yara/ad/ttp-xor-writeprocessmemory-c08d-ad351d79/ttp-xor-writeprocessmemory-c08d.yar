rule TTP_XOR_WriteProcessMemory_c08d {
  strings:
    $key_c08d = { 97 ff [2] a5 dd [2] a3 e8 [2] 8d e8 [2] b2 f4 }

  condition:
    any of them
}