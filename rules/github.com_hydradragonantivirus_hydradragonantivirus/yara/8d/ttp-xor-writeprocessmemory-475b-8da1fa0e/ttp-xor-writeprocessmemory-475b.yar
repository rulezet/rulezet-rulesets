rule TTP_XOR_WriteProcessMemory_475b {
  strings:
    $key_475b = { 10 29 [2] 22 0b [2] 24 3e [2] 0a 3e [2] 35 22 }

  condition:
    any of them
}