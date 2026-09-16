rule TTP_XOR_WriteProcessMemory_535c {
  strings:
    $key_535c = { 04 2e [2] 36 0c [2] 30 39 [2] 1e 39 [2] 21 25 }

  condition:
    any of them
}