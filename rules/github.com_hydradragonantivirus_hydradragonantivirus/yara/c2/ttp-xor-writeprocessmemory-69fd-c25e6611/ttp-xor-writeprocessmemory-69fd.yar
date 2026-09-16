rule TTP_XOR_WriteProcessMemory_69fd {
  strings:
    $key_69fd = { 3e 8f [2] 0c ad [2] 0a 98 [2] 24 98 [2] 1b 84 }

  condition:
    any of them
}