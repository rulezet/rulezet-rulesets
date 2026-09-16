rule TTP_XOR_WriteProcessMemory_629c {
  strings:
    $key_629c = { 35 ee [2] 07 cc [2] 01 f9 [2] 2f f9 [2] 10 e5 }

  condition:
    any of them
}