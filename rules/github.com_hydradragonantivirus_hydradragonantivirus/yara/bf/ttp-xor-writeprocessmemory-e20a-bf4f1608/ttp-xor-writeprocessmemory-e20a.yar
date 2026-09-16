rule TTP_XOR_WriteProcessMemory_e20a {
  strings:
    $key_e20a = { b5 78 [2] 87 5a [2] 81 6f [2] af 6f [2] 90 73 }

  condition:
    any of them
}