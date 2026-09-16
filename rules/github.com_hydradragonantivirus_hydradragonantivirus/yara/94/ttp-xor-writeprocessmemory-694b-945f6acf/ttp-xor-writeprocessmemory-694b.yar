rule TTP_XOR_WriteProcessMemory_694b {
  strings:
    $key_694b = { 3e 39 [2] 0c 1b [2] 0a 2e [2] 24 2e [2] 1b 32 }

  condition:
    any of them
}