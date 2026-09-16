rule TTP_XOR_WriteProcessMemory_27be {
  strings:
    $key_27be = { 70 cc [2] 42 ee [2] 44 db [2] 6a db [2] 55 c7 }

  condition:
    any of them
}