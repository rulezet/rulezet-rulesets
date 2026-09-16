rule TTP_XOR_WriteProcessMemory_21dd {
  strings:
    $key_21dd = { 76 af [2] 44 8d [2] 42 b8 [2] 6c b8 [2] 53 a4 }

  condition:
    any of them
}