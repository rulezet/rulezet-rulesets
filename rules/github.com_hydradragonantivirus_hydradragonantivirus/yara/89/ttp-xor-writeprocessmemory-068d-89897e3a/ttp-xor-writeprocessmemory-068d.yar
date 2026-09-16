rule TTP_XOR_WriteProcessMemory_068d {
  strings:
    $key_068d = { 51 ff [2] 63 dd [2] 65 e8 [2] 4b e8 [2] 74 f4 }

  condition:
    any of them
}