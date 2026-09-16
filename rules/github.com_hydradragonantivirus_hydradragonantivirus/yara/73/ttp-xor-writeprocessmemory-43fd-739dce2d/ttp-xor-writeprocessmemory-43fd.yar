rule TTP_XOR_WriteProcessMemory_43fd {
  strings:
    $key_43fd = { 14 8f [2] 26 ad [2] 20 98 [2] 0e 98 [2] 31 84 }

  condition:
    any of them
}