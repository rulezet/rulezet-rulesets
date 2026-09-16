rule TTP_XOR_WriteProcessMemory_e2fd {
  strings:
    $key_e2fd = { b5 8f [2] 87 ad [2] 81 98 [2] af 98 [2] 90 84 }

  condition:
    any of them
}