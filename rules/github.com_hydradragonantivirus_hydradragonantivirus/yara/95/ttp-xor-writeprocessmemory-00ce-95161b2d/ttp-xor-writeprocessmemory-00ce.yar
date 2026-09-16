rule TTP_XOR_WriteProcessMemory_00ce {
  strings:
    $key_00ce = { 57 bc [2] 65 9e [2] 63 ab [2] 4d ab [2] 72 b7 }

  condition:
    any of them
}