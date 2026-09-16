rule TTP_XOR_WriteProcessMemory_552b {
  strings:
    $key_552b = { 02 59 [2] 30 7b [2] 36 4e [2] 18 4e [2] 27 52 }

  condition:
    any of them
}