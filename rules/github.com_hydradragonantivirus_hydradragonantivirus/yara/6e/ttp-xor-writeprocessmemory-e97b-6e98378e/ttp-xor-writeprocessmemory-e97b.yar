rule TTP_XOR_WriteProcessMemory_e97b {
  strings:
    $key_e97b = { be 09 [2] 8c 2b [2] 8a 1e [2] a4 1e [2] 9b 02 }

  condition:
    any of them
}