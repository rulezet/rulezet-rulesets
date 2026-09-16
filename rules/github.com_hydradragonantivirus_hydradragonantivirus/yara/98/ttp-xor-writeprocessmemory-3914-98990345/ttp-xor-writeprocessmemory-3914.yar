rule TTP_XOR_WriteProcessMemory_3914 {
  strings:
    $key_3914 = { 6e 66 [2] 5c 44 [2] 5a 71 [2] 74 71 [2] 4b 6d }

  condition:
    any of them
}