rule TTP_XOR_WriteProcessMemory_fab8 {
  strings:
    $key_fab8 = { ad ca [2] 9f e8 [2] 99 dd [2] b7 dd [2] 88 c1 }

  condition:
    any of them
}