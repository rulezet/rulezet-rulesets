rule TTP_XOR_WriteProcessMemory_3bfe {
  strings:
    $key_3bfe = { 6c 8c [2] 5e ae [2] 58 9b [2] 76 9b [2] 49 87 }

  condition:
    any of them
}