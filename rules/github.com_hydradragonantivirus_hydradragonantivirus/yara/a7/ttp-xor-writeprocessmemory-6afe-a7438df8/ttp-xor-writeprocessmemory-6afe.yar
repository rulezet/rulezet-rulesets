rule TTP_XOR_WriteProcessMemory_6afe {
  strings:
    $key_6afe = { 3d 8c [2] 0f ae [2] 09 9b [2] 27 9b [2] 18 87 }

  condition:
    any of them
}