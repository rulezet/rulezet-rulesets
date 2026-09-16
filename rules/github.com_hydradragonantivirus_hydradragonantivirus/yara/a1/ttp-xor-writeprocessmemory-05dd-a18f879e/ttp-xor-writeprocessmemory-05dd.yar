rule TTP_XOR_WriteProcessMemory_05dd {
  strings:
    $key_05dd = { 52 af [2] 60 8d [2] 66 b8 [2] 48 b8 [2] 77 a4 }

  condition:
    any of them
}