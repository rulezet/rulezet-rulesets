rule TTP_XOR_WriteProcessMemory_69e3 {
  strings:
    $key_69e3 = { 3e 91 [2] 0c b3 [2] 0a 86 [2] 24 86 [2] 1b 9a }

  condition:
    any of them
}