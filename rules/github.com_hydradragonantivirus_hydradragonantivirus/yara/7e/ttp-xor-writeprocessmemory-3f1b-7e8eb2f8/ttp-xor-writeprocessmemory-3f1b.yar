rule TTP_XOR_WriteProcessMemory_3f1b {
  strings:
    $key_3f1b = { 68 69 [2] 5a 4b [2] 5c 7e [2] 72 7e [2] 4d 62 }

  condition:
    any of them
}