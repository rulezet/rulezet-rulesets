rule TTP_XOR_WriteProcessMemory_3923 {
  strings:
    $key_3923 = { 6e 51 [2] 5c 73 [2] 5a 46 [2] 74 46 [2] 4b 5a }

  condition:
    any of them
}