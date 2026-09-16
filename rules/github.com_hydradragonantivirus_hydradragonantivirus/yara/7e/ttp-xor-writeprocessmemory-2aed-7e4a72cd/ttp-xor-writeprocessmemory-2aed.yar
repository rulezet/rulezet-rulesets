rule TTP_XOR_WriteProcessMemory_2aed {
  strings:
    $key_2aed = { 7d 9f [2] 4f bd [2] 49 88 [2] 67 88 [2] 58 94 }

  condition:
    any of them
}