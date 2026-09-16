rule TTP_XOR_WriteProcessMemory_e99c {
  strings:
    $key_e99c = { be ee [2] 8c cc [2] 8a f9 [2] a4 f9 [2] 9b e5 }

  condition:
    any of them
}