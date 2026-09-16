rule TTP_XOR_WriteProcessMemory_29e8 {
  strings:
    $key_29e8 = { 7e 9a [2] 4c b8 [2] 4a 8d [2] 64 8d [2] 5b 91 }

  condition:
    any of them
}