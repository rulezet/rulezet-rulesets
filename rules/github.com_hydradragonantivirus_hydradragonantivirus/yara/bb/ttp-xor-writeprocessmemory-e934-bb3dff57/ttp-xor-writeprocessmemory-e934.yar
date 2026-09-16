rule TTP_XOR_WriteProcessMemory_e934 {
  strings:
    $key_e934 = { be 46 [2] 8c 64 [2] 8a 51 [2] a4 51 [2] 9b 4d }

  condition:
    any of them
}