rule TTP_XOR_WriteProcessMemory_2901 {
  strings:
    $key_2901 = { 7e 73 [2] 4c 51 [2] 4a 64 [2] 64 64 [2] 5b 78 }

  condition:
    any of them
}