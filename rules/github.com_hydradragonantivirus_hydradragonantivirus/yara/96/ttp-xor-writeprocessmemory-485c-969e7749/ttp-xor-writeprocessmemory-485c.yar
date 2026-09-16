rule TTP_XOR_WriteProcessMemory_485c {
  strings:
    $key_485c = { 1f 2e [2] 2d 0c [2] 2b 39 [2] 05 39 [2] 3a 25 }

  condition:
    any of them
}