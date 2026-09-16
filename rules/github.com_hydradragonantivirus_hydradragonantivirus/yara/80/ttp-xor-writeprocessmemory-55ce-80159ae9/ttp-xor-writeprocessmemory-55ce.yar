rule TTP_XOR_WriteProcessMemory_55ce {
  strings:
    $key_55ce = { 02 bc [2] 30 9e [2] 36 ab [2] 18 ab [2] 27 b7 }

  condition:
    any of them
}