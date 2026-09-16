rule TTP_XOR_WriteProcessMemory_37dd {
  strings:
    $key_37dd = { 60 af [2] 52 8d [2] 54 b8 [2] 7a b8 [2] 45 a4 }

  condition:
    any of them
}