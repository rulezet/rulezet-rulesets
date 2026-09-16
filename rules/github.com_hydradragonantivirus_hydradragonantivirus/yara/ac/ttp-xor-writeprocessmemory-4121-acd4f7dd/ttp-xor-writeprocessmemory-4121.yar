rule TTP_XOR_WriteProcessMemory_4121 {
  strings:
    $key_4121 = { 16 53 [2] 24 71 [2] 22 44 [2] 0c 44 [2] 33 58 }

  condition:
    any of them
}