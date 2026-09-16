rule TTP_XOR_WriteProcessMemory_e23c {
  strings:
    $key_e23c = { b5 4e [2] 87 6c [2] 81 59 [2] af 59 [2] 90 45 }

  condition:
    any of them
}