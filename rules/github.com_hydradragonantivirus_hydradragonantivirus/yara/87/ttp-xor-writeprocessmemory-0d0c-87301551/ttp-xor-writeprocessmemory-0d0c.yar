rule TTP_XOR_WriteProcessMemory_0d0c {
  strings:
    $key_0d0c = { 5a 7e [2] 68 5c [2] 6e 69 [2] 40 69 [2] 7f 75 }

  condition:
    any of them
}