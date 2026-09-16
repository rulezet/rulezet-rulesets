rule TTP_XOR_WriteProcessMemory_6c4d {
  strings:
    $key_6c4d = { 3b 3f [2] 09 1d [2] 0f 28 [2] 21 28 [2] 1e 34 }

  condition:
    any of them
}