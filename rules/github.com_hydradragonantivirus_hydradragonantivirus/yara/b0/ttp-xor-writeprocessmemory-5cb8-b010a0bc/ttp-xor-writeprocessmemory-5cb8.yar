rule TTP_XOR_WriteProcessMemory_5cb8 {
  strings:
    $key_5cb8 = { 0b ca [2] 39 e8 [2] 3f dd [2] 11 dd [2] 2e c1 }

  condition:
    any of them
}