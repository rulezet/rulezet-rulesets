rule TTP_XOR_WriteProcessMemory_03dd {
  strings:
    $key_03dd = { 54 af [2] 66 8d [2] 60 b8 [2] 4e b8 [2] 71 a4 }

  condition:
    any of them
}