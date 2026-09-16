rule TTP_XOR_WriteProcessMemory_7338 {
  strings:
    $key_7338 = { 24 4a [2] 16 68 [2] 10 5d [2] 3e 5d [2] 01 41 }

  condition:
    any of them
}