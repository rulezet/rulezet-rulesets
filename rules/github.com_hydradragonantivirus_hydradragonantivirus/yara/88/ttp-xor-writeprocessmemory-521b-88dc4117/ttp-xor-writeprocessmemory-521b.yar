rule TTP_XOR_WriteProcessMemory_521b {
  strings:
    $key_521b = { 05 69 [2] 37 4b [2] 31 7e [2] 1f 7e [2] 20 62 }

  condition:
    any of them
}