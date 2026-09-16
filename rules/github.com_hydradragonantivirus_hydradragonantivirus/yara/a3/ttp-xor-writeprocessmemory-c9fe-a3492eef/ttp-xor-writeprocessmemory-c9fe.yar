rule TTP_XOR_WriteProcessMemory_c9fe {
  strings:
    $key_c9fe = { 9e 8c [2] ac ae [2] aa 9b [2] 84 9b [2] bb 87 }

  condition:
    any of them
}