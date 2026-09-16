rule TTP_XOR_WriteProcessMemory_cc04 {
  strings:
    $key_cc04 = { 9b 76 [2] a9 54 [2] af 61 [2] 81 61 [2] be 7d }

  condition:
    any of them
}