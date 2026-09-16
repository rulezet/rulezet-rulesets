rule TTP_XOR_WriteProcessMemory_6db8 {
  strings:
    $key_6db8 = { 3a ca [2] 08 e8 [2] 0e dd [2] 20 dd [2] 1f c1 }

  condition:
    any of them
}