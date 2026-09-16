rule TTP_XOR_WriteProcessMemory_03fd {
  strings:
    $key_03fd = { 54 8f [2] 66 ad [2] 60 98 [2] 4e 98 [2] 71 84 }

  condition:
    any of them
}