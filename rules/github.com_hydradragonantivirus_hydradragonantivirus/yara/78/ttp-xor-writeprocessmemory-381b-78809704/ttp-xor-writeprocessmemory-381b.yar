rule TTP_XOR_WriteProcessMemory_381b {
  strings:
    $key_381b = { 6f 69 [2] 5d 4b [2] 5b 7e [2] 75 7e [2] 4a 62 }

  condition:
    any of them
}