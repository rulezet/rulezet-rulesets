rule TTP_XOR_WriteProcessMemory_026b {
  strings:
    $key_026b = { 55 19 [2] 67 3b [2] 61 0e [2] 4f 0e [2] 70 12 }

  condition:
    any of them
}