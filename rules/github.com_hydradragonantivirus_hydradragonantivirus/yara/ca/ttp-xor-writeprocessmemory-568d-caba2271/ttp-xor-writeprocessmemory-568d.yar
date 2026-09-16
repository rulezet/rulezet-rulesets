rule TTP_XOR_WriteProcessMemory_568d {
  strings:
    $key_568d = { 01 ff [2] 33 dd [2] 35 e8 [2] 1b e8 [2] 24 f4 }

  condition:
    any of them
}