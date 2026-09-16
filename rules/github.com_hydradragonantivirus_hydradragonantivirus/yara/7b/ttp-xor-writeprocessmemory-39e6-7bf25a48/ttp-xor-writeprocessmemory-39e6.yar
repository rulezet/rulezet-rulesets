rule TTP_XOR_WriteProcessMemory_39e6 {
  strings:
    $key_39e6 = { 6e 94 [2] 5c b6 [2] 5a 83 [2] 74 83 [2] 4b 9f }

  condition:
    any of them
}