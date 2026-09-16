rule TTP_XOR_WriteProcessMemory_99fd {
  strings:
    $key_99fd = { ce 8f [2] fc ad [2] fa 98 [2] d4 98 [2] eb 84 }

  condition:
    any of them
}