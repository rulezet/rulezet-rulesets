rule TTP_XOR_WriteProcessMemory_f8b8 {
  strings:
    $key_f8b8 = { af ca [2] 9d e8 [2] 9b dd [2] b5 dd [2] 8a c1 }

  condition:
    any of them
}