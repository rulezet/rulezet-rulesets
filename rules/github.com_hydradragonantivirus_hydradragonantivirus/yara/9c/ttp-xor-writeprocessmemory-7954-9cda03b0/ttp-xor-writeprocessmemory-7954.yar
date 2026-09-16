rule TTP_XOR_WriteProcessMemory_7954 {
  strings:
    $key_7954 = { 2e 26 [2] 1c 04 [2] 1a 31 [2] 34 31 [2] 0b 2d }

  condition:
    any of them
}