rule TTP_XOR_WriteProcessMemory_228d {
  strings:
    $key_228d = { 75 ff [2] 47 dd [2] 41 e8 [2] 6f e8 [2] 50 f4 }

  condition:
    any of them
}