rule TTP_XOR_WriteProcessMemory_6b64 {
  strings:
    $key_6b64 = { 3c 16 [2] 0e 34 [2] 08 01 [2] 26 01 [2] 19 1d }

  condition:
    any of them
}