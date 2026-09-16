rule TTP_XOR_WriteProcessMemory_e209 {
  strings:
    $key_e209 = { b5 7b [2] 87 59 [2] 81 6c [2] af 6c [2] 90 70 }

  condition:
    any of them
}