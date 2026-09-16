rule TTP_XOR_WriteProcessMemory_c8be {
  strings:
    $key_c8be = { 9f cc [2] ad ee [2] ab db [2] 85 db [2] ba c7 }

  condition:
    any of them
}