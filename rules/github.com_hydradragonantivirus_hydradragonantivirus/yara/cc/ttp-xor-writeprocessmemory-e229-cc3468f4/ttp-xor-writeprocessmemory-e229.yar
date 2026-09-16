rule TTP_XOR_WriteProcessMemory_e229 {
  strings:
    $key_e229 = { b5 5b [2] 87 79 [2] 81 4c [2] af 4c [2] 90 50 }

  condition:
    any of them
}