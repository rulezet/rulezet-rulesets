rule TTP_XOR_WriteProcessMemory_088d {
  strings:
    $key_088d = { 5f ff [2] 6d dd [2] 6b e8 [2] 45 e8 [2] 7a f4 }

  condition:
    any of them
}