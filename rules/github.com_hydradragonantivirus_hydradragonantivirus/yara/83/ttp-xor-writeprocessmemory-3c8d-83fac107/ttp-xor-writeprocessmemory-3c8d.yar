rule TTP_XOR_WriteProcessMemory_3c8d {
  strings:
    $key_3c8d = { 6b ff [2] 59 dd [2] 5f e8 [2] 71 e8 [2] 4e f4 }

  condition:
    any of them
}