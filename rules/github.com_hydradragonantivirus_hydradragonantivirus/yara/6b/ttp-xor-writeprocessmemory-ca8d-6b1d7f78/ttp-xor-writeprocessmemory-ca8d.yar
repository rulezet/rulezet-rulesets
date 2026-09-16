rule TTP_XOR_WriteProcessMemory_ca8d {
  strings:
    $key_ca8d = { 9d ff [2] af dd [2] a9 e8 [2] 87 e8 [2] b8 f4 }

  condition:
    any of them
}