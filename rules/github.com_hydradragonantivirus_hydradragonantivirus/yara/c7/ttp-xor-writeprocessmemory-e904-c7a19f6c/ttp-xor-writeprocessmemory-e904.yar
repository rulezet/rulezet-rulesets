rule TTP_XOR_WriteProcessMemory_e904 {
  strings:
    $key_e904 = { be 76 [2] 8c 54 [2] 8a 61 [2] a4 61 [2] 9b 7d }

  condition:
    any of them
}