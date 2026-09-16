rule TTP_XOR_WriteProcessMemory_3afe {
  strings:
    $key_3afe = { 6d 8c [2] 5f ae [2] 59 9b [2] 77 9b [2] 48 87 }

  condition:
    any of them
}