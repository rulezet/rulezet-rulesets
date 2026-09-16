rule TTP_XOR_WriteProcessMemory_d08d {
  strings:
    $key_d08d = { 87 ff [2] b5 dd [2] b3 e8 [2] 9d e8 [2] a2 f4 }

  condition:
    any of them
}