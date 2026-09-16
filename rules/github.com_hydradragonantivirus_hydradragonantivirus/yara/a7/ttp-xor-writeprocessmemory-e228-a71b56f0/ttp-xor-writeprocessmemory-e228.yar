rule TTP_XOR_WriteProcessMemory_e228 {
  strings:
    $key_e228 = { b5 5a [2] 87 78 [2] 81 4d [2] af 4d [2] 90 51 }

  condition:
    any of them
}