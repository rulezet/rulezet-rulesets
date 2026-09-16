rule TTP_XOR_WriteProcessMemory_4227 {
  strings:
    $key_4227 = { 15 55 [2] 27 77 [2] 21 42 [2] 0f 42 [2] 30 5e }

  condition:
    any of them
}