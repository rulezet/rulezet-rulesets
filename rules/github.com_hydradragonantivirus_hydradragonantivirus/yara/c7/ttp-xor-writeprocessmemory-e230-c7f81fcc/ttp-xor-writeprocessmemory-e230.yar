rule TTP_XOR_WriteProcessMemory_e230 {
  strings:
    $key_e230 = { b5 42 [2] 87 60 [2] 81 55 [2] af 55 [2] 90 49 }

  condition:
    any of them
}