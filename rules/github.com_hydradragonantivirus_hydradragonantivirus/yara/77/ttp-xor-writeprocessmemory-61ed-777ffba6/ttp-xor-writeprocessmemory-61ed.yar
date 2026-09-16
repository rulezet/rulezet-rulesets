rule TTP_XOR_WriteProcessMemory_61ed {
  strings:
    $key_61ed = { 36 9f [2] 04 bd [2] 02 88 [2] 2c 88 [2] 13 94 }

  condition:
    any of them
}