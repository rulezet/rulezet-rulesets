rule TTP_XOR_WriteProcessMemory_111c {
  strings:
    $key_111c = { 46 6e [2] 74 4c [2] 72 79 [2] 5c 79 [2] 63 65 }

  condition:
    any of them
}