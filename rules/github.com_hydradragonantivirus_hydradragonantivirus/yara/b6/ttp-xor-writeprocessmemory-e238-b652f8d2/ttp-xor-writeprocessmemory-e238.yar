rule TTP_XOR_WriteProcessMemory_e238 {
  strings:
    $key_e238 = { b5 4a [2] 87 68 [2] 81 5d [2] af 5d [2] 90 41 }

  condition:
    any of them
}