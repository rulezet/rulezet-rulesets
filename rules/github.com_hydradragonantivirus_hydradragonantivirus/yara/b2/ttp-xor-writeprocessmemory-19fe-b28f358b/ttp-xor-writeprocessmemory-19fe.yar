rule TTP_XOR_WriteProcessMemory_19fe {
  strings:
    $key_19fe = { 4e 8c [2] 7c ae [2] 7a 9b [2] 54 9b [2] 6b 87 }

  condition:
    any of them
}