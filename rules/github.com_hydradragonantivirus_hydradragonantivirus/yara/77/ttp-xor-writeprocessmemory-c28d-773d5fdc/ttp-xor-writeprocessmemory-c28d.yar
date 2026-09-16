rule TTP_XOR_WriteProcessMemory_c28d {
  strings:
    $key_c28d = { 95 ff [2] a7 dd [2] a1 e8 [2] 8f e8 [2] b0 f4 }

  condition:
    any of them
}