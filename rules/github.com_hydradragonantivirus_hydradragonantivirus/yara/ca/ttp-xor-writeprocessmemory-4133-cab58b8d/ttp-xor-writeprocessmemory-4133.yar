rule TTP_XOR_WriteProcessMemory_4133 {
  strings:
    $key_4133 = { 16 41 [2] 24 63 [2] 22 56 [2] 0c 56 [2] 33 4a }

  condition:
    any of them
}