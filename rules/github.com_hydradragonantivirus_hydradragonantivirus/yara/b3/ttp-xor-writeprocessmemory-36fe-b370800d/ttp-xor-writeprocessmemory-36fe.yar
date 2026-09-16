rule TTP_XOR_WriteProcessMemory_36fe {
  strings:
    $key_36fe = { 61 8c [2] 53 ae [2] 55 9b [2] 7b 9b [2] 44 87 }

  condition:
    any of them
}