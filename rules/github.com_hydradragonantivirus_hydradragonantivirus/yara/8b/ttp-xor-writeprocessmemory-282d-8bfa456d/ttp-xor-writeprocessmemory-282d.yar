rule TTP_XOR_WriteProcessMemory_282d {
  strings:
    $key_282d = { 7f 5f [2] 4d 7d [2] 4b 48 [2] 65 48 [2] 5a 54 }

  condition:
    any of them
}