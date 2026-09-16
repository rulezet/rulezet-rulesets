rule TTP_XOR_WriteProcessMemory_0ab8 {
  strings:
    $key_0ab8 = { 5d ca [2] 6f e8 [2] 69 dd [2] 47 dd [2] 78 c1 }

  condition:
    any of them
}