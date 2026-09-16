rule TTP_XOR_WriteProcessMemory_268d {
  strings:
    $key_268d = { 71 ff [2] 43 dd [2] 45 e8 [2] 6b e8 [2] 54 f4 }

  condition:
    any of them
}