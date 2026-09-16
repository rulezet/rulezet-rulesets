rule TTP_XOR_WriteProcessMemory_e2ee {
  strings:
    $key_e2ee = { b5 9c [2] 87 be [2] 81 8b [2] af 8b [2] 90 97 }

  condition:
    any of them
}