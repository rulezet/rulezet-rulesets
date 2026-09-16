rule TTP_XOR_WriteProcessMemory_20fd {
  strings:
    $key_20fd = { 77 8f [2] 45 ad [2] 43 98 [2] 6d 98 [2] 52 84 }

  condition:
    any of them
}