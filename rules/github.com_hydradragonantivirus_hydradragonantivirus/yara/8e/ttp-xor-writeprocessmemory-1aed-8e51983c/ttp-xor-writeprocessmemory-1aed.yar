rule TTP_XOR_WriteProcessMemory_1aed {
  strings:
    $key_1aed = { 4d 9f [2] 7f bd [2] 79 88 [2] 57 88 [2] 68 94 }

  condition:
    any of them
}