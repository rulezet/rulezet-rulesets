rule TTP_XOR_WriteProcessMemory_e231 {
  strings:
    $key_e231 = { b5 43 [2] 87 61 [2] 81 54 [2] af 54 [2] 90 48 }

  condition:
    any of them
}