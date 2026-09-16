rule TTP_XOR_WriteProcessMemory_3f34 {
  strings:
    $key_3f34 = { 68 46 [2] 5a 64 [2] 5c 51 [2] 72 51 [2] 4d 4d }

  condition:
    any of them
}