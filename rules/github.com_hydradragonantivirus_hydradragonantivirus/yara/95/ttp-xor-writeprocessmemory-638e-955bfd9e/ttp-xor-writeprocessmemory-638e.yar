rule TTP_XOR_WriteProcessMemory_638e {
  strings:
    $key_638e = { 34 fc [2] 06 de [2] 00 eb [2] 2e eb [2] 11 f7 }

  condition:
    any of them
}