rule TTP_XOR_WriteProcessMemory_192b {
  strings:
    $key_192b = { 4e 59 [2] 7c 7b [2] 7a 4e [2] 54 4e [2] 6b 52 }

  condition:
    any of them
}