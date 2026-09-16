rule TTP_XOR_WriteProcessMemory_1cb8 {
  strings:
    $key_1cb8 = { 4b ca [2] 79 e8 [2] 7f dd [2] 51 dd [2] 6e c1 }

  condition:
    any of them
}