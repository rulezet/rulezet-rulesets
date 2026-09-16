rule TTP_XOR_WriteProcessMemory_c894 {
  strings:
    $key_c894 = { 9f e6 [2] ad c4 [2] ab f1 [2] 85 f1 [2] ba ed }

  condition:
    any of them
}