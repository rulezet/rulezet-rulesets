rule TTP_XOR_WriteProcessMemory_7aed {
  strings:
    $key_7aed = { 2d 9f [2] 1f bd [2] 19 88 [2] 37 88 [2] 08 94 }

  condition:
    any of them
}