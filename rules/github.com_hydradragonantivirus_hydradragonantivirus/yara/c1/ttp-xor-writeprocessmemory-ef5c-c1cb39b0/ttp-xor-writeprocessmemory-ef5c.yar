rule TTP_XOR_WriteProcessMemory_ef5c {
  strings:
    $key_ef5c = { b8 2e [2] 8a 0c [2] 8c 39 [2] a2 39 [2] 9d 25 }

  condition:
    any of them
}