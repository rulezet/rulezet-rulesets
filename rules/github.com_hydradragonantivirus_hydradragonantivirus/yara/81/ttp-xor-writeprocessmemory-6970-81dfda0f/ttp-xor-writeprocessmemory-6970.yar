rule TTP_XOR_WriteProcessMemory_6970 {
  strings:
    $key_6970 = { 3e 02 [2] 0c 20 [2] 0a 15 [2] 24 15 [2] 1b 09 }

  condition:
    any of them
}