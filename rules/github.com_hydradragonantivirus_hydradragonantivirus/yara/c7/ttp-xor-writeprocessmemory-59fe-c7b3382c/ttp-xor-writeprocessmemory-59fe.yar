rule TTP_XOR_WriteProcessMemory_59fe {
  strings:
    $key_59fe = { 0e 8c [2] 3c ae [2] 3a 9b [2] 14 9b [2] 2b 87 }

  condition:
    any of them
}