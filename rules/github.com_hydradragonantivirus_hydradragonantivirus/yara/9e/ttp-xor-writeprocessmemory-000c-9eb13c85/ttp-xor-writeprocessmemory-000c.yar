rule TTP_XOR_WriteProcessMemory_000c {
  strings:
    $key_000c = { 57 7e [2] 65 5c [2] 63 69 [2] 4d 69 [2] 72 75 }

  condition:
    any of them
}