rule TTP_XOR_WriteProcessMemory_42fd {
  strings:
    $key_42fd = { 15 8f [2] 27 ad [2] 21 98 [2] 0f 98 [2] 30 84 }

  condition:
    any of them
}