rule TTP_XOR_WriteProcessMemory_e22c {
  strings:
    $key_e22c = { b5 5e [2] 87 7c [2] 81 49 [2] af 49 [2] 90 55 }

  condition:
    any of them
}