rule TTP_XOR_WriteProcessMemory_3f61 {
  strings:
    $key_3f61 = { 68 13 [2] 5a 31 [2] 5c 04 [2] 72 04 [2] 4d 18 }

  condition:
    any of them
}