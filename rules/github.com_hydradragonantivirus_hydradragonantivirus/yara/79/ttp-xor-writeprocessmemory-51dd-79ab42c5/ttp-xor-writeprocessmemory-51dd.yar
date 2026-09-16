rule TTP_XOR_WriteProcessMemory_51dd {
  strings:
    $key_51dd = { 06 af [2] 34 8d [2] 32 b8 [2] 1c b8 [2] 23 a4 }

  condition:
    any of them
}