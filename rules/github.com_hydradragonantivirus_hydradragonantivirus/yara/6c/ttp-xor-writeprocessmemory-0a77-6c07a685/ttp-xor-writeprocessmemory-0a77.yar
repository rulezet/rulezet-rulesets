rule TTP_XOR_WriteProcessMemory_0a77 {
  strings:
    $key_0a77 = { 5d 05 [2] 6f 27 [2] 69 12 [2] 47 12 [2] 78 0e }

  condition:
    any of them
}