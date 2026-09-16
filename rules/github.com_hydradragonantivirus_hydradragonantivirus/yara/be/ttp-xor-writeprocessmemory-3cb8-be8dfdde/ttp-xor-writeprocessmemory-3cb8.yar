rule TTP_XOR_WriteProcessMemory_3cb8 {
  strings:
    $key_3cb8 = { 6b ca [2] 59 e8 [2] 5f dd [2] 71 dd [2] 4e c1 }

  condition:
    any of them
}