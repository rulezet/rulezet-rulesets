rule TTP_XOR_WriteProcessMemory_0a61 {
  strings:
    $key_0a61 = { 5d 13 [2] 6f 31 [2] 69 04 [2] 47 04 [2] 78 18 }

  condition:
    any of them
}