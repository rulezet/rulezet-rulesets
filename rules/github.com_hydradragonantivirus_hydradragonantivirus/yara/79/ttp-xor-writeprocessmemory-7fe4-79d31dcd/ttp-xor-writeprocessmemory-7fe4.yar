rule TTP_XOR_WriteProcessMemory_7fe4 {
  strings:
    $key_7fe4 = { 28 96 [2] 1a b4 [2] 1c 81 [2] 32 81 [2] 0d 9d }

  condition:
    any of them
}