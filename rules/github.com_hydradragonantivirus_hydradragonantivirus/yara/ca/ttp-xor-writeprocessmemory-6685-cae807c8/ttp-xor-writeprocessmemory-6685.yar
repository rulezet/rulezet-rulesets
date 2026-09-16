rule TTP_XOR_WriteProcessMemory_6685 {
  strings:
    $key_6685 = { 31 f7 [2] 03 d5 [2] 05 e0 [2] 2b e0 [2] 14 fc }

  condition:
    any of them
}