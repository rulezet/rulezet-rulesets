rule TTP_XOR_WriteProcessMemory_2ed2 {
  strings:
    $key_2ed2 = { 79 a0 [2] 4b 82 [2] 4d b7 [2] 63 b7 [2] 5c ab }

  condition:
    any of them
}