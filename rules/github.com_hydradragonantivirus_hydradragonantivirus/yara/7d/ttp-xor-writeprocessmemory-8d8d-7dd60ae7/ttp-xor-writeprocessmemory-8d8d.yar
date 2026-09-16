rule TTP_XOR_WriteProcessMemory_8d8d {
  strings:
    $key_8d8d = { da ff [2] e8 dd [2] ee e8 [2] c0 e8 [2] ff f4 }

  condition:
    any of them
}