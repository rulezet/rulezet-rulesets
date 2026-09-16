rule TTP_XOR_WriteProcessMemory_f58d {
  strings:
    $key_f58d = { a2 ff [2] 90 dd [2] 96 e8 [2] b8 e8 [2] 87 f4 }

  condition:
    any of them
}