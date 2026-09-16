rule TTP_XOR_WriteProcessMemory_e227 {
  strings:
    $key_e227 = { b5 55 [2] 87 77 [2] 81 42 [2] af 42 [2] 90 5e }

  condition:
    any of them
}