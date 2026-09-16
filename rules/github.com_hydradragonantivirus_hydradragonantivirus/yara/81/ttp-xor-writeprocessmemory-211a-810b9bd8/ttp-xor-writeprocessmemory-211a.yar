rule TTP_XOR_WriteProcessMemory_211a {
  strings:
    $key_211a = { 76 68 [2] 44 4a [2] 42 7f [2] 6c 7f [2] 53 63 }

  condition:
    any of them
}