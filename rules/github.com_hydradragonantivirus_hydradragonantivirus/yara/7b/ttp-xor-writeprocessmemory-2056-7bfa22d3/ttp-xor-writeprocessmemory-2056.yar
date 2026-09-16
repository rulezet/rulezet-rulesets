rule TTP_XOR_WriteProcessMemory_2056 {
  strings:
    $key_2056 = { 77 24 [2] 45 06 [2] 43 33 [2] 6d 33 [2] 52 2f }

  condition:
    any of them
}