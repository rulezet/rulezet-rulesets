rule TTP_XOR_WriteProcessMemory_0223 {
  strings:
    $key_0223 = { 55 51 [2] 67 73 [2] 61 46 [2] 4f 46 [2] 70 5a }

  condition:
    any of them
}