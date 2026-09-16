rule TTP_XOR_WriteProcessMemory_02be {
  strings:
    $key_02be = { 55 cc [2] 67 ee [2] 61 db [2] 4f db [2] 70 c7 }

  condition:
    any of them
}