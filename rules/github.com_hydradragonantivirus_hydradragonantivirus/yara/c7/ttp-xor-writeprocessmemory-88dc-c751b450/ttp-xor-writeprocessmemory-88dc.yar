rule TTP_XOR_WriteProcessMemory_88dc {
  strings:
    $key_88dc = { df ae [2] ed 8c [2] eb b9 [2] c5 b9 [2] fa a5 }

  condition:
    any of them
}