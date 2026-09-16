rule TTP_XOR_WriteProcessMemory_7afe {
  strings:
    $key_7afe = { 2d 8c [2] 1f ae [2] 19 9b [2] 37 9b [2] 08 87 }

  condition:
    any of them
}