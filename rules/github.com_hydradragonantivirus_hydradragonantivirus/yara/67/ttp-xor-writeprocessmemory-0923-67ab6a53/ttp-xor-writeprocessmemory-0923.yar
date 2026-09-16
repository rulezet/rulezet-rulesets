rule TTP_XOR_WriteProcessMemory_0923 {
  strings:
    $key_0923 = { 5e 51 [2] 6c 73 [2] 6a 46 [2] 44 46 [2] 7b 5a }

  condition:
    any of them
}