rule TTP_XOR_WriteProcessMemory_c893 {
  strings:
    $key_c893 = { 9f e1 [2] ad c3 [2] ab f6 [2] 85 f6 [2] ba ea }

  condition:
    any of them
}