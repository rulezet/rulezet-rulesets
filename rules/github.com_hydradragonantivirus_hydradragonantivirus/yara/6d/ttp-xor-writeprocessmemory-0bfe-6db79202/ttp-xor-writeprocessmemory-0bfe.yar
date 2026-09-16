rule TTP_XOR_WriteProcessMemory_0bfe {
  strings:
    $key_0bfe = { 5c 8c [2] 6e ae [2] 68 9b [2] 46 9b [2] 79 87 }

  condition:
    any of them
}