rule TTP_XOR_WriteProcessMemory_5227 {
  strings:
    $key_5227 = { 05 55 [2] 37 77 [2] 31 42 [2] 1f 42 [2] 20 5e }

  condition:
    any of them
}