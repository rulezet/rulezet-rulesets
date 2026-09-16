rule TTP_XOR_WriteProcessMemory_79e3 {
  strings:
    $key_79e3 = { 2e 91 [2] 1c b3 [2] 1a 86 [2] 34 86 [2] 0b 9a }

  condition:
    any of them
}