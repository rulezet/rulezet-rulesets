rule TTP_XOR_WriteProcessMemory_516d {
  strings:
    $key_516d = { 06 1f [2] 34 3d [2] 32 08 [2] 1c 08 [2] 23 14 }

  condition:
    any of them
}