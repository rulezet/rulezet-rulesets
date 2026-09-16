rule TTP_XOR_WriteProcessMemory_a18b {
  strings:
    $key_a18b = { f6 f9 [2] c4 db [2] c2 ee [2] ec ee [2] d3 f2 }

  condition:
    any of them
}