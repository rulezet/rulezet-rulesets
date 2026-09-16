rule TTP_XOR_WriteProcessMemory_6aed {
  strings:
    $key_6aed = { 3d 9f [2] 0f bd [2] 09 88 [2] 27 88 [2] 18 94 }

  condition:
    any of them
}