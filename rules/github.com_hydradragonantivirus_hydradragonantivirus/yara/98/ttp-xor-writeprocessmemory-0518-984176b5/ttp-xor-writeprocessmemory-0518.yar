rule TTP_XOR_WriteProcessMemory_0518 {
  strings:
    $key_0518 = { 52 6a [2] 60 48 [2] 66 7d [2] 48 7d [2] 77 61 }

  condition:
    any of them
}