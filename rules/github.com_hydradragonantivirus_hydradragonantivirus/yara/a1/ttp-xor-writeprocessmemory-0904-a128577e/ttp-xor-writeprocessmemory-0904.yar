rule TTP_XOR_WriteProcessMemory_0904 {
  strings:
    $key_0904 = { 5e 76 [2] 6c 54 [2] 6a 61 [2] 44 61 [2] 7b 7d }

  condition:
    any of them
}