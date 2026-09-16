rule TTP_XOR_WriteProcessMemory_0afe {
  strings:
    $key_0afe = { 5d 8c [2] 6f ae [2] 69 9b [2] 47 9b [2] 78 87 }

  condition:
    any of them
}