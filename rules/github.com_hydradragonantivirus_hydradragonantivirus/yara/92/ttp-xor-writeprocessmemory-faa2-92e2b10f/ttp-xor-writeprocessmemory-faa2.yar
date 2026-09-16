rule TTP_XOR_WriteProcessMemory_faa2 {
  strings:
    $key_faa2 = { ad d0 [2] 9f f2 [2] 99 c7 [2] b7 c7 [2] 88 db }

  condition:
    any of them
}