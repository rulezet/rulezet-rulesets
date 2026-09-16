rule TTP_XOR_WriteProcessMemory_52ed {
  strings:
    $key_52ed = { 05 9f [2] 37 bd [2] 31 88 [2] 1f 88 [2] 20 94 }

  condition:
    any of them
}