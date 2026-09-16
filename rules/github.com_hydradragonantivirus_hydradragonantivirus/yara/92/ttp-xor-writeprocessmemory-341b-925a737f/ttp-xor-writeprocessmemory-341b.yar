rule TTP_XOR_WriteProcessMemory_341b {
  strings:
    $key_341b = { 63 69 [2] 51 4b [2] 57 7e [2] 79 7e [2] 46 62 }

  condition:
    any of them
}