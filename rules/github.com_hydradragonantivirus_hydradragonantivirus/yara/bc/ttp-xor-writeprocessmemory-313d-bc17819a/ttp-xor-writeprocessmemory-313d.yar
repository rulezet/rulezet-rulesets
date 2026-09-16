rule TTP_XOR_WriteProcessMemory_313d {
  strings:
    $key_313d = { 66 4f [2] 54 6d [2] 52 58 [2] 7c 58 [2] 43 44 }

  condition:
    any of them
}