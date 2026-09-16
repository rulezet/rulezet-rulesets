rule TTP_XOR_WriteProcessMemory_645c {
  strings:
    $key_645c = { 33 2e [2] 01 0c [2] 07 39 [2] 29 39 [2] 16 25 }

  condition:
    any of them
}