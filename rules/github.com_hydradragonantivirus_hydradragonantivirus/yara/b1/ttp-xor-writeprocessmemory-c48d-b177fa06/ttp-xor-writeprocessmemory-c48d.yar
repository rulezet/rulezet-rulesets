rule TTP_XOR_WriteProcessMemory_c48d {
  strings:
    $key_c48d = { 93 ff [2] a1 dd [2] a7 e8 [2] 89 e8 [2] b6 f4 }

  condition:
    any of them
}