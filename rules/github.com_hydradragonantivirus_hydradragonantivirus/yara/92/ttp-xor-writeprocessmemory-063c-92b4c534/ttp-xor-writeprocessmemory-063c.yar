rule TTP_XOR_WriteProcessMemory_063c {
  strings:
    $key_063c = { 51 4e [2] 63 6c [2] 65 59 [2] 4b 59 [2] 74 45 }

  condition:
    any of them
}