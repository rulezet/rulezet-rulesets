rule TTP_XOR_WriteProcessMemory_2949 {
  strings:
    $key_2949 = { 7e 3b [2] 4c 19 [2] 4a 2c [2] 64 2c [2] 5b 30 }

  condition:
    any of them
}