rule TTP_XOR_WriteProcessMemory_668d {
  strings:
    $key_668d = { 31 ff [2] 03 dd [2] 05 e8 [2] 2b e8 [2] 14 f4 }

  condition:
    any of them
}