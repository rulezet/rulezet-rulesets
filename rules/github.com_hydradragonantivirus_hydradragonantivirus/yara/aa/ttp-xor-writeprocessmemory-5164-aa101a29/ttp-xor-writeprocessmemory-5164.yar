rule TTP_XOR_WriteProcessMemory_5164 {
  strings:
    $key_5164 = { 06 16 [2] 34 34 [2] 32 01 [2] 1c 01 [2] 23 1d }

  condition:
    any of them
}