rule TTP_XOR_WriteProcessMemory_f4b8 {
  strings:
    $key_f4b8 = { a3 ca [2] 91 e8 [2] 97 dd [2] b9 dd [2] 86 c1 }

  condition:
    any of them
}