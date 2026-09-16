rule TTP_XOR_WriteProcessMemory_0aed {
  strings:
    $key_0aed = { 5d 9f [2] 6f bd [2] 69 88 [2] 47 88 [2] 78 94 }

  condition:
    any of them
}