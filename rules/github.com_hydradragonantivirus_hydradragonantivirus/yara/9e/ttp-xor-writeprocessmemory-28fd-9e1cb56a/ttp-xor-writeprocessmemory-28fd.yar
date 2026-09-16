rule TTP_XOR_WriteProcessMemory_28fd {
  strings:
    $key_28fd = { 7f 8f [2] 4d ad [2] 4b 98 [2] 65 98 [2] 5a 84 }

  condition:
    any of them
}