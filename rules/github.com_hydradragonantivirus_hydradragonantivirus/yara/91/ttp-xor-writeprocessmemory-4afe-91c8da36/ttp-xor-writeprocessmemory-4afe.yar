rule TTP_XOR_WriteProcessMemory_4afe {
  strings:
    $key_4afe = { 1d 8c [2] 2f ae [2] 29 9b [2] 07 9b [2] 38 87 }

  condition:
    any of them
}