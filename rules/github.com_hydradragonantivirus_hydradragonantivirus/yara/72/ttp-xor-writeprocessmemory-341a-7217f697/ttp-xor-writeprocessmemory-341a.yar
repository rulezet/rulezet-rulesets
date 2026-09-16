rule TTP_XOR_WriteProcessMemory_341a {
  strings:
    $key_341a = { 63 68 [2] 51 4a [2] 57 7f [2] 79 7f [2] 46 63 }

  condition:
    any of them
}