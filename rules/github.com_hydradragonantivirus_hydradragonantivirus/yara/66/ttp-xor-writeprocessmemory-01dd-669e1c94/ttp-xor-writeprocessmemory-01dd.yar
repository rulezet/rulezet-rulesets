rule TTP_XOR_WriteProcessMemory_01dd {
  strings:
    $key_01dd = { 56 af [2] 64 8d [2] 62 b8 [2] 4c b8 [2] 73 a4 }

  condition:
    any of them
}