rule TTP_XOR_WriteProcessMemory_09e4 {
  strings:
    $key_09e4 = { 5e 96 [2] 6c b4 [2] 6a 81 [2] 44 81 [2] 7b 9d }

  condition:
    any of them
}