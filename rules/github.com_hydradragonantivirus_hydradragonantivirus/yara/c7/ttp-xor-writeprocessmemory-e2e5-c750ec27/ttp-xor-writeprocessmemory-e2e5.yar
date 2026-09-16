rule TTP_XOR_WriteProcessMemory_e2e5 {
  strings:
    $key_e2e5 = { b5 97 [2] 87 b5 [2] 81 80 [2] af 80 [2] 90 9c }

  condition:
    any of them
}