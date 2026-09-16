rule TTP_XOR_WriteProcessMemory_6094 {
  strings:
    $key_6094 = { 37 e6 [2] 05 c4 [2] 03 f1 [2] 2d f1 [2] 12 ed }

  condition:
    any of them
}