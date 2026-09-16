rule TTP_XOR_WriteProcessMemory_681b {
  strings:
    $key_681b = { 3f 69 [2] 0d 4b [2] 0b 7e [2] 25 7e [2] 1a 62 }

  condition:
    any of them
}