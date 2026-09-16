rule TTP_XOR_WriteProcessMemory_eafe {
  strings:
    $key_eafe = { bd 8c [2] 8f ae [2] 89 9b [2] a7 9b [2] 98 87 }

  condition:
    any of them
}