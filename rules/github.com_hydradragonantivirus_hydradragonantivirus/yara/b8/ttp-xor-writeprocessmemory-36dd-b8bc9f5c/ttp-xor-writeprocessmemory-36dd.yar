rule TTP_XOR_WriteProcessMemory_36dd {
  strings:
    $key_36dd = { 61 af [2] 53 8d [2] 55 b8 [2] 7b b8 [2] 44 a4 }

  condition:
    any of them
}