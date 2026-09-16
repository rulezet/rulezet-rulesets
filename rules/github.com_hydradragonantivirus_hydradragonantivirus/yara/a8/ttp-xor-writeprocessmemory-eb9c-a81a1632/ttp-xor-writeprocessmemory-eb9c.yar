rule TTP_XOR_WriteProcessMemory_eb9c {
  strings:
    $key_eb9c = { bc ee [2] 8e cc [2] 88 f9 [2] a6 f9 [2] 99 e5 }

  condition:
    any of them
}