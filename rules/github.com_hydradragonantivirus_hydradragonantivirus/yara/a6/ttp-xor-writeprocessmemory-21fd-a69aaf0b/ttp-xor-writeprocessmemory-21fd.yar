rule TTP_XOR_WriteProcessMemory_21fd {
  strings:
    $key_21fd = { 76 8f [2] 44 ad [2] 42 98 [2] 6c 98 [2] 53 84 }

  condition:
    any of them
}