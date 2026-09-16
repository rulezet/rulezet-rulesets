rule TTP_XOR_WriteProcessMemory_1fe4 {
  strings:
    $key_1fe4 = { 48 96 [2] 7a b4 [2] 7c 81 [2] 52 81 [2] 6d 9d }

  condition:
    any of them
}