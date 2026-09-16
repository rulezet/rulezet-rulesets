rule TTP_XOR_WriteProcessMemory_24fe {
  strings:
    $key_24fe = { 73 8c [2] 41 ae [2] 47 9b [2] 69 9b [2] 56 87 }

  condition:
    any of them
}