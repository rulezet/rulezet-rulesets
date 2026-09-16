rule TTP_XOR_WriteProcessMemory_2931 {
  strings:
    $key_2931 = { 7e 43 [2] 4c 61 [2] 4a 54 [2] 64 54 [2] 5b 48 }

  condition:
    any of them
}