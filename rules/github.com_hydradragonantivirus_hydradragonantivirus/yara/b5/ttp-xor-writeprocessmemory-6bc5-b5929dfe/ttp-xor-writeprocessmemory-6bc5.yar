rule TTP_XOR_WriteProcessMemory_6bc5 {
  strings:
    $key_6bc5 = { 3c b7 [2] 0e 95 [2] 08 a0 [2] 26 a0 [2] 19 bc }

  condition:
    any of them
}