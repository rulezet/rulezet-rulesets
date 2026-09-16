rule TTP_XOR_WriteProcessMemory_128d {
  strings:
    $key_128d = { 45 ff [2] 77 dd [2] 71 e8 [2] 5f e8 [2] 60 f4 }

  condition:
    any of them
}