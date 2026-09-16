rule TTP_XOR_WriteProcessMemory_177d {
  strings:
    $key_177d = { 40 0f [2] 72 2d [2] 74 18 [2] 5a 18 [2] 65 04 }

  condition:
    any of them
}