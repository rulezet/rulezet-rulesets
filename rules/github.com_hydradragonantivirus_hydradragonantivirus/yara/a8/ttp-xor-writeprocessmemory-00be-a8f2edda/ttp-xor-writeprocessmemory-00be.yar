rule TTP_XOR_WriteProcessMemory_00be {
  strings:
    $key_00be = { 57 cc [2] 65 ee [2] 63 db [2] 4d db [2] 72 c7 }

  condition:
    any of them
}