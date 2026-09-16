rule TTP_XOR_WriteProcessMemory_140c {
  strings:
    $key_140c = { 43 7e [2] 71 5c [2] 77 69 [2] 59 69 [2] 66 75 }

  condition:
    any of them
}