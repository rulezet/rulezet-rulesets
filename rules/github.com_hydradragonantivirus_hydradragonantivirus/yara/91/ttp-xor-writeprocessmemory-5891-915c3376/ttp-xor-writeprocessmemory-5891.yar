rule TTP_XOR_WriteProcessMemory_5891 {
  strings:
    $key_5891 = { 0f e3 [2] 3d c1 [2] 3b f4 [2] 15 f4 [2] 2a e8 }

  condition:
    any of them
}