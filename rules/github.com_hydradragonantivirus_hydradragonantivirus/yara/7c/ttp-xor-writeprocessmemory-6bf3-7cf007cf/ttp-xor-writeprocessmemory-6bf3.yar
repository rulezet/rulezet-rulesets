rule TTP_XOR_WriteProcessMemory_6bf3 {
  strings:
    $key_6bf3 = { 3c 81 [2] 0e a3 [2] 08 96 [2] 26 96 [2] 19 8a }

  condition:
    any of them
}