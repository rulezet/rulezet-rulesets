rule TTP_XOR_WriteProcessMemory_061c {
  strings:
    $key_061c = { 51 6e [2] 63 4c [2] 65 79 [2] 4b 79 [2] 74 65 }

  condition:
    any of them
}