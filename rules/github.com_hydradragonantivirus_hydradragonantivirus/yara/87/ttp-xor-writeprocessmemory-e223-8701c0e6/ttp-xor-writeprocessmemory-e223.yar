rule TTP_XOR_WriteProcessMemory_e223 {
  strings:
    $key_e223 = { b5 51 [2] 87 73 [2] 81 46 [2] af 46 [2] 90 5a }

  condition:
    any of them
}