rule TTP_XOR_WriteProcessMemory_6056 {
  strings:
    $key_6056 = { 37 24 [2] 05 06 [2] 03 33 [2] 2d 33 [2] 12 2f }

  condition:
    any of them
}