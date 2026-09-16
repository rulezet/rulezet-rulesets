rule TTP_XOR_WriteProcessMemory_2923 {
  strings:
    $key_2923 = { 7e 51 [2] 4c 73 [2] 4a 46 [2] 64 46 [2] 5b 5a }

  condition:
    any of them
}