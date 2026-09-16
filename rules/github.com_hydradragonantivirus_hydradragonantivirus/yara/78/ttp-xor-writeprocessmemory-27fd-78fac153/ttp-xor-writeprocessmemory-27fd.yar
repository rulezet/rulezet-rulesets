rule TTP_XOR_WriteProcessMemory_27fd {
  strings:
    $key_27fd = { 70 8f [2] 42 ad [2] 44 98 [2] 6a 98 [2] 55 84 }

  condition:
    any of them
}