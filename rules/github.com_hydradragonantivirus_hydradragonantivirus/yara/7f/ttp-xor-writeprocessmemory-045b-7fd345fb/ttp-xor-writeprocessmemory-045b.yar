rule TTP_XOR_WriteProcessMemory_045b {
  strings:
    $key_045b = { 53 29 [2] 61 0b [2] 67 3e [2] 49 3e [2] 76 22 }

  condition:
    any of them
}