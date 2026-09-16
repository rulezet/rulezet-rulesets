rule TTP_XOR_WriteProcessMemory_aab8 {
  strings:
    $key_aab8 = { fd ca [2] cf e8 [2] c9 dd [2] e7 dd [2] d8 c1 }

  condition:
    any of them
}