rule TTP_XOR_WriteProcessMemory_52fd {
  strings:
    $key_52fd = { 05 8f [2] 37 ad [2] 31 98 [2] 1f 98 [2] 20 84 }

  condition:
    any of them
}