rule TTP_XOR_WriteProcessMemory_b2fd {
  strings:
    $key_b2fd = { e5 8f [2] d7 ad [2] d1 98 [2] ff 98 [2] c0 84 }

  condition:
    any of them
}