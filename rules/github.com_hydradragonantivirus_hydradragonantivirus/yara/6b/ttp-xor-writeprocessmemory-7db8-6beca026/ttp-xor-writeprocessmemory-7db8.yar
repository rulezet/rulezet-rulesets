rule TTP_XOR_WriteProcessMemory_7db8 {
  strings:
    $key_7db8 = { 2a ca [2] 18 e8 [2] 1e dd [2] 30 dd [2] 0f c1 }

  condition:
    any of them
}