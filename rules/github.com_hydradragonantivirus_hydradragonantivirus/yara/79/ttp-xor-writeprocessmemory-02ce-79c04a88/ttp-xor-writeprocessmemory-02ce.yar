rule TTP_XOR_WriteProcessMemory_02ce {
  strings:
    $key_02ce = { 55 bc [2] 67 9e [2] 61 ab [2] 4f ab [2] 70 b7 }

  condition:
    any of them
}