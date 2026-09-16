rule TTP_XOR_WriteProcessMemory_31dd {
  strings:
    $key_31dd = { 66 af [2] 54 8d [2] 52 b8 [2] 7c b8 [2] 43 a4 }

  condition:
    any of them
}