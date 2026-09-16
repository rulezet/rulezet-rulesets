rule TTP_XOR_WriteProcessMemory_0a24 {
  strings:
    $key_0a24 = { 5d 56 [2] 6f 74 [2] 69 41 [2] 47 41 [2] 78 5d }

  condition:
    any of them
}