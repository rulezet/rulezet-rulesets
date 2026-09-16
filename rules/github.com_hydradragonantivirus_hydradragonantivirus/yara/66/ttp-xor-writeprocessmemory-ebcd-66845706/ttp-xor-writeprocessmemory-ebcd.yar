rule TTP_XOR_WriteProcessMemory_ebcd {
  strings:
    $key_ebcd = { bc bf [2] 8e 9d [2] 88 a8 [2] a6 a8 [2] 99 b4 }

  condition:
    any of them
}