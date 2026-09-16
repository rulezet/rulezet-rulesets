rule TTP_XOR_WriteProcessMemory_48ed {
  strings:
    $key_48ed = { 1f 9f [2] 2d bd [2] 2b 88 [2] 05 88 [2] 3a 94 }

  condition:
    any of them
}