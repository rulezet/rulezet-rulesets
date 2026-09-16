rule TTP_XOR_WriteProcessMemory_090b {
  strings:
    $key_090b = { 5e 79 [2] 6c 5b [2] 6a 6e [2] 44 6e [2] 7b 72 }

  condition:
    any of them
}