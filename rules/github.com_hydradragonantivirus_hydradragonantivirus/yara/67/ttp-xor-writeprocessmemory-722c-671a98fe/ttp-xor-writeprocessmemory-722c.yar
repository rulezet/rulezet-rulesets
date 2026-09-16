rule TTP_XOR_WriteProcessMemory_722c {
  strings:
    $key_722c = { 25 5e [2] 17 7c [2] 11 49 [2] 3f 49 [2] 00 55 }

  condition:
    any of them
}