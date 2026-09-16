rule TTP_XOR_WriteProcessMemory_45ed {
  strings:
    $key_45ed = { 12 9f [2] 20 bd [2] 26 88 [2] 08 88 [2] 37 94 }

  condition:
    any of them
}