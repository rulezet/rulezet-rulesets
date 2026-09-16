rule TTP_XOR_WriteProcessMemory_e21a {
  strings:
    $key_e21a = { b5 68 [2] 87 4a [2] 81 7f [2] af 7f [2] 90 63 }

  condition:
    any of them
}