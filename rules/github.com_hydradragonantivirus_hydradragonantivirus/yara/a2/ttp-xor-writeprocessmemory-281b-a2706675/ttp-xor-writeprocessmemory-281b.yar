rule TTP_XOR_WriteProcessMemory_281b {
  strings:
    $key_281b = { 7f 69 [2] 4d 4b [2] 4b 7e [2] 65 7e [2] 5a 62 }

  condition:
    any of them
}