rule TTP_XOR_WriteProcessMemory_0db8 {
  strings:
    $key_0db8 = { 5a ca [2] 68 e8 [2] 6e dd [2] 40 dd [2] 7f c1 }

  condition:
    any of them
}