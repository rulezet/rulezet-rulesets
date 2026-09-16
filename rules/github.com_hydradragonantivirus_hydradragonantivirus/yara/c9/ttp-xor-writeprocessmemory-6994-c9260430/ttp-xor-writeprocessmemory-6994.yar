rule TTP_XOR_WriteProcessMemory_6994 {
  strings:
    $key_6994 = { 3e e6 [2] 0c c4 [2] 0a f1 [2] 24 f1 [2] 1b ed }

  condition:
    any of them
}