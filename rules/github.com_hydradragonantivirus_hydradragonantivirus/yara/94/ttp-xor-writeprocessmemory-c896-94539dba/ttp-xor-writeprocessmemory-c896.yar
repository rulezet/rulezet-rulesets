rule TTP_XOR_WriteProcessMemory_c896 {
  strings:
    $key_c896 = { 9f e4 [2] ad c6 [2] ab f3 [2] 85 f3 [2] ba ef }

  condition:
    any of them
}