rule TTP_XOR_WriteProcessMemory_6c0d {
  strings:
    $key_6c0d = { 3b 7f [2] 09 5d [2] 0f 68 [2] 21 68 [2] 1e 74 }

  condition:
    any of them
}