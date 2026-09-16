rule TTP_XOR_WriteProcessMemory_c18d {
  strings:
    $key_c18d = { 96 ff [2] a4 dd [2] a2 e8 [2] 8c e8 [2] b3 f4 }

  condition:
    any of them
}