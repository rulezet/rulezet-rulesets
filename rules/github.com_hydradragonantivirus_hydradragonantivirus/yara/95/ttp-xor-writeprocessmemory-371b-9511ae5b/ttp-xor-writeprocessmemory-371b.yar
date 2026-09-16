rule TTP_XOR_WriteProcessMemory_371b {
  strings:
    $key_371b = { 60 69 [2] 52 4b [2] 54 7e [2] 7a 7e [2] 45 62 }

  condition:
    any of them
}