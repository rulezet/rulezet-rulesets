rule TTP_XOR_WriteProcessMemory_1bc5 {
  strings:
    $key_1bc5 = { 4c b7 [2] 7e 95 [2] 78 a0 [2] 56 a0 [2] 69 bc }

  condition:
    any of them
}