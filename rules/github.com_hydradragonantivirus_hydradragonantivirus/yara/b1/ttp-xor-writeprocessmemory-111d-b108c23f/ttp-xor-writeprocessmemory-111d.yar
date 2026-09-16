rule TTP_XOR_WriteProcessMemory_111d {
  strings:
    $key_111d = { 46 6f [2] 74 4d [2] 72 78 [2] 5c 78 [2] 63 64 }

  condition:
    any of them
}