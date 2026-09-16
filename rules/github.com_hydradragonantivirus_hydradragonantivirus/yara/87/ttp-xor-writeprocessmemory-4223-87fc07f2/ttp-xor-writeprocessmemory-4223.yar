rule TTP_XOR_WriteProcessMemory_4223 {
  strings:
    $key_4223 = { 15 51 [2] 27 73 [2] 21 46 [2] 0f 46 [2] 30 5a }

  condition:
    any of them
}