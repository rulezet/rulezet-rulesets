rule TTP_XOR_WriteProcessMemory_552e {
  strings:
    $key_552e = { 02 5c [2] 30 7e [2] 36 4b [2] 18 4b [2] 27 57 }

  condition:
    any of them
}