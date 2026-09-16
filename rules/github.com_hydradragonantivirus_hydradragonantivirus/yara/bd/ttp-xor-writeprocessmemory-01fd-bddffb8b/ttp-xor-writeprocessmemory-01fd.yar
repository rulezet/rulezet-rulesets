rule TTP_XOR_WriteProcessMemory_01fd {
  strings:
    $key_01fd = { 56 8f [2] 64 ad [2] 62 98 [2] 4c 98 [2] 73 84 }

  condition:
    any of them
}