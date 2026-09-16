rule TTP_XOR_WriteProcessMemory_e213 {
  strings:
    $key_e213 = { b5 61 [2] 87 43 [2] 81 76 [2] af 76 [2] 90 6a }

  condition:
    any of them
}