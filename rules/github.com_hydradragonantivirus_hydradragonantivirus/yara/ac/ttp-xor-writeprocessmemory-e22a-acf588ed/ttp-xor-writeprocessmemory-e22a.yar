rule TTP_XOR_WriteProcessMemory_e22a {
  strings:
    $key_e22a = { b5 58 [2] 87 7a [2] 81 4f [2] af 4f [2] 90 53 }

  condition:
    any of them
}