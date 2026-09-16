rule TTP_XOR_WriteProcessMemory_2227 {
  strings:
    $key_2227 = { 75 55 [2] 47 77 [2] 41 42 [2] 6f 42 [2] 50 5e }

  condition:
    any of them
}