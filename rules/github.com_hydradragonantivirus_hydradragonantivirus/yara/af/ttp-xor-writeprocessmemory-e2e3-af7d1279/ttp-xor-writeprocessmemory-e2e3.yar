rule TTP_XOR_WriteProcessMemory_e2e3 {
  strings:
    $key_e2e3 = { b5 91 [2] 87 b3 [2] 81 86 [2] af 86 [2] 90 9a }

  condition:
    any of them
}