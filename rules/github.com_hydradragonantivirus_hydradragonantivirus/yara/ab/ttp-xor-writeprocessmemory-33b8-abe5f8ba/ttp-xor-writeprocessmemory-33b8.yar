rule TTP_XOR_WriteProcessMemory_33b8 {
  strings:
    $key_33b8 = { 64 ca [2] 56 e8 [2] 50 dd [2] 7e dd [2] 41 c1 }

  condition:
    any of them
}