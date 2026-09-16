rule TTP_XOR_WriteProcessMemory_79fd {
  strings:
    $key_79fd = { 2e 8f [2] 1c ad [2] 1a 98 [2] 34 98 [2] 0b 84 }

  condition:
    any of them
}