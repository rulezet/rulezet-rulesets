rule TTP_XOR_WriteProcessMemory_171d {
  strings:
    $key_171d = { 40 6f [2] 72 4d [2] 74 78 [2] 5a 78 [2] 65 64 }

  condition:
    any of them
}