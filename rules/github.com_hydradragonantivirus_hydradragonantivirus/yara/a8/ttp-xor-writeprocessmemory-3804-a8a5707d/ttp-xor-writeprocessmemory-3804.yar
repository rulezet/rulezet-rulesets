rule TTP_XOR_WriteProcessMemory_3804 {
  strings:
    $key_3804 = { 6f 76 [2] 5d 54 [2] 5b 61 [2] 75 61 [2] 4a 7d }

  condition:
    any of them
}