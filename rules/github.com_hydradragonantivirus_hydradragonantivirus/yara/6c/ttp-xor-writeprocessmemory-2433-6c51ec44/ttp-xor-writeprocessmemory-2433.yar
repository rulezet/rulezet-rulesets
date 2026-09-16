rule TTP_XOR_WriteProcessMemory_2433 {
  strings:
    $key_2433 = { 73 41 [2] 41 63 [2] 47 56 [2] 69 56 [2] 56 4a }

  condition:
    any of them
}