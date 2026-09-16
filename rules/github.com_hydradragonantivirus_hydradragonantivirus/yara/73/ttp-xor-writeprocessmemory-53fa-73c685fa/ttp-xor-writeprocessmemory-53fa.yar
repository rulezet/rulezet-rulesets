rule TTP_XOR_WriteProcessMemory_53fa {
  strings:
    $key_53fa = { 04 88 [2] 36 aa [2] 30 9f [2] 1e 9f [2] 21 83 }

  condition:
    any of them
}