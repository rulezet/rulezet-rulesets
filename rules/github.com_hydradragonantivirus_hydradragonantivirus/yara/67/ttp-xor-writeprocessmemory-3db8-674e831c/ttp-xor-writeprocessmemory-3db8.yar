rule TTP_XOR_WriteProcessMemory_3db8 {
  strings:
    $key_3db8 = { 6a ca [2] 58 e8 [2] 5e dd [2] 70 dd [2] 4f c1 }

  condition:
    any of them
}