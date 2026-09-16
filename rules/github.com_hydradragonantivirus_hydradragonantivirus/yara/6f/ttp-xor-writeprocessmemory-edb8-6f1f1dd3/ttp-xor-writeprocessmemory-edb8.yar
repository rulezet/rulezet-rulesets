rule TTP_XOR_WriteProcessMemory_edb8 {
  strings:
    $key_edb8 = { ba ca [2] 88 e8 [2] 8e dd [2] a0 dd [2] 9f c1 }

  condition:
    any of them
}