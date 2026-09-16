rule TTP_XOR_WriteProcessMemory_76fd {
  strings:
    $key_76fd = { 21 8f [2] 13 ad [2] 15 98 [2] 3b 98 [2] 04 84 }

  condition:
    any of them
}