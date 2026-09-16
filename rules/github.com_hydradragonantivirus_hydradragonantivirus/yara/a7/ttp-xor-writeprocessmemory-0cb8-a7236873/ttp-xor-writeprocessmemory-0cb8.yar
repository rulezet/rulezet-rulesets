rule TTP_XOR_WriteProcessMemory_0cb8 {
  strings:
    $key_0cb8 = { 5b ca [2] 69 e8 [2] 6f dd [2] 41 dd [2] 7e c1 }

  condition:
    any of them
}