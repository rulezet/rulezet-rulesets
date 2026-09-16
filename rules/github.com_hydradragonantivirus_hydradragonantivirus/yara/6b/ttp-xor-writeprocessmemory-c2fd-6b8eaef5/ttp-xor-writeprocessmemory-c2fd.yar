rule TTP_XOR_WriteProcessMemory_c2fd {
  strings:
    $key_c2fd = { 95 8f [2] a7 ad [2] a1 98 [2] 8f 98 [2] b0 84 }

  condition:
    any of them
}