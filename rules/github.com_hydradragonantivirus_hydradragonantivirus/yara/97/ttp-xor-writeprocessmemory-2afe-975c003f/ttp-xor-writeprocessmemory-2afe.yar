rule TTP_XOR_WriteProcessMemory_2afe {
  strings:
    $key_2afe = { 7d 8c [2] 4f ae [2] 49 9b [2] 67 9b [2] 58 87 }

  condition:
    any of them
}