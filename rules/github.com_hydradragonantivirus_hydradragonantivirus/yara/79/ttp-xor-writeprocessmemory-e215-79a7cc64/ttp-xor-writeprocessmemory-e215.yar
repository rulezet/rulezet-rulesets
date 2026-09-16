rule TTP_XOR_WriteProcessMemory_e215 {
  strings:
    $key_e215 = { b5 67 [2] 87 45 [2] 81 70 [2] af 70 [2] 90 6c }

  condition:
    any of them
}