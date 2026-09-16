rule TTP_XOR_WriteProcessMemory_e3be {
  strings:
    $key_e3be = { b4 cc [2] 86 ee [2] 80 db [2] ae db [2] 91 c7 }

  condition:
    any of them
}