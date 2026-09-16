rule TTP_XOR_WriteProcessMemory_24b8 {
  strings:
    $key_24b8 = { 73 ca [2] 41 e8 [2] 47 dd [2] 69 dd [2] 56 c1 }

  condition:
    any of them
}