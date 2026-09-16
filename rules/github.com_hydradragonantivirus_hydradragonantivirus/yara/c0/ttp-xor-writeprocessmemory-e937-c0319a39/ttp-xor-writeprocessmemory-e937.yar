rule TTP_XOR_WriteProcessMemory_e937 {
  strings:
    $key_e937 = { be 45 [2] 8c 67 [2] 8a 52 [2] a4 52 [2] 9b 4e }

  condition:
    any of them
}