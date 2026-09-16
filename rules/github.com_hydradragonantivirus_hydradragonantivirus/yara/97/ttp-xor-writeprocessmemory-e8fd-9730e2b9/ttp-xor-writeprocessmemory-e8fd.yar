rule TTP_XOR_WriteProcessMemory_e8fd {
  strings:
    $key_e8fd = { bf 8f [2] 8d ad [2] 8b 98 [2] a5 98 [2] 9a 84 }

  condition:
    any of them
}