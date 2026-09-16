rule TTP_XOR_WriteProcessMemory_e239 {
  strings:
    $key_e239 = { b5 4b [2] 87 69 [2] 81 5c [2] af 5c [2] 90 40 }

  condition:
    any of them
}