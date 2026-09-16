rule TTP_XOR_WriteProcessMemory_75fd {
  strings:
    $key_75fd = { 22 8f [2] 10 ad [2] 16 98 [2] 38 98 [2] 07 84 }

  condition:
    any of them
}