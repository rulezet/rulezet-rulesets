rule TTP_XOR_WriteProcessMemory_2cb8 {
  strings:
    $key_2cb8 = { 7b ca [2] 49 e8 [2] 4f dd [2] 61 dd [2] 5e c1 }

  condition:
    any of them
}