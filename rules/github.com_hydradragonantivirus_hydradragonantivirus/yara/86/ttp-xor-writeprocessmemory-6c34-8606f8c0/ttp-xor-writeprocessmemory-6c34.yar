rule TTP_XOR_WriteProcessMemory_6c34 {
  strings:
    $key_6c34 = { 3b 46 [2] 09 64 [2] 0f 51 [2] 21 51 [2] 1e 4d }

  condition:
    any of them
}