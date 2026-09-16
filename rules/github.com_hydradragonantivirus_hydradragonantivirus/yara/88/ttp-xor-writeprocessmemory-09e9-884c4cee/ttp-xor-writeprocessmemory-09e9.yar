rule TTP_XOR_WriteProcessMemory_09e9 {
  strings:
    $key_09e9 = { 5e 9b [2] 6c b9 [2] 6a 8c [2] 44 8c [2] 7b 90 }

  condition:
    any of them
}