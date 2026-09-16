rule TTP_XOR_WriteProcessMemory_5423 {
  strings:
    $key_5423 = { 03 51 [2] 31 73 [2] 37 46 [2] 19 46 [2] 26 5a }

  condition:
    any of them
}