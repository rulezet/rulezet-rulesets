rule TTP_XOR_WriteProcessMemory_e0be {
  strings:
    $key_e0be = { b7 cc [2] 85 ee [2] 83 db [2] ad db [2] 92 c7 }

  condition:
    any of them
}