rule TTP_XOR_WriteProcessMemory_172c {
  strings:
    $key_172c = { 40 5e [2] 72 7c [2] 74 49 [2] 5a 49 [2] 65 55 }

  condition:
    any of them
}