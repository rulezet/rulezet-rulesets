rule TTP_XOR_WriteProcessMemory_2434 {
  strings:
    $key_2434 = { 73 46 [2] 41 64 [2] 47 51 [2] 69 51 [2] 56 4d }

  condition:
    any of them
}