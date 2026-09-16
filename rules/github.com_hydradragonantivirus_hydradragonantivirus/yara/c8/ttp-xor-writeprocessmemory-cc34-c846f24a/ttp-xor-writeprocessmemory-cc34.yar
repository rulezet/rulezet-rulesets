rule TTP_XOR_WriteProcessMemory_cc34 {
  strings:
    $key_cc34 = { 9b 46 [2] a9 64 [2] af 51 [2] 81 51 [2] be 4d }

  condition:
    any of them
}