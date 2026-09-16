rule TTP_XOR_WriteProcessMemory_61fd {
  strings:
    $key_61fd = { 36 8f [2] 04 ad [2] 02 98 [2] 2c 98 [2] 13 84 }

  condition:
    any of them
}