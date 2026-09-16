rule TTP_XOR_WriteProcessMemory_248d {
  strings:
    $key_248d = { 73 ff [2] 41 dd [2] 47 e8 [2] 69 e8 [2] 56 f4 }

  condition:
    any of them
}