rule TTP_XOR_WriteProcessMemory_b28d {
  strings:
    $key_b28d = { e5 ff [2] d7 dd [2] d1 e8 [2] ff e8 [2] c0 f4 }

  condition:
    any of them
}