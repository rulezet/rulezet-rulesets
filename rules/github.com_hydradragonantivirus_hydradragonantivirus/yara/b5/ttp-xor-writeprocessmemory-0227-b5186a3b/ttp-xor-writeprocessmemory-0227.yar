rule TTP_XOR_WriteProcessMemory_0227 {
  strings:
    $key_0227 = { 55 55 [2] 67 77 [2] 61 42 [2] 4f 42 [2] 70 5e }

  condition:
    any of them
}