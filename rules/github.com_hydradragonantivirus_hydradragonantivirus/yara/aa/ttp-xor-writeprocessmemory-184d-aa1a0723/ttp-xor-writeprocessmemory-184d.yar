rule TTP_XOR_WriteProcessMemory_184d {
  strings:
    $key_184d = { 4f 3f [2] 7d 1d [2] 7b 28 [2] 55 28 [2] 6a 34 }

  condition:
    any of them
}