rule TTP_XOR_WriteProcessMemory_e235 {
  strings:
    $key_e235 = { b5 47 [2] 87 65 [2] 81 50 [2] af 50 [2] 90 4c }

  condition:
    any of them
}