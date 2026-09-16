rule TTP_XOR_WriteProcessMemory_541b {
  strings:
    $key_541b = { 03 69 [2] 31 4b [2] 37 7e [2] 19 7e [2] 26 62 }

  condition:
    any of them
}