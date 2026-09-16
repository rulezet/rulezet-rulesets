rule TTP_XOR_WriteProcessMemory_097b {
  strings:
    $key_097b = { 5e 09 [2] 6c 2b [2] 6a 1e [2] 44 1e [2] 7b 02 }

  condition:
    any of them
}