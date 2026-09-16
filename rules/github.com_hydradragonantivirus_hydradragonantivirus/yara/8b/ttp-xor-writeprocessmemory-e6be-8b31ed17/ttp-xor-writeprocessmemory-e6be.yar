rule TTP_XOR_WriteProcessMemory_e6be {
  strings:
    $key_e6be = { b1 cc [2] 83 ee [2] 85 db [2] ab db [2] 94 c7 }

  condition:
    any of them
}