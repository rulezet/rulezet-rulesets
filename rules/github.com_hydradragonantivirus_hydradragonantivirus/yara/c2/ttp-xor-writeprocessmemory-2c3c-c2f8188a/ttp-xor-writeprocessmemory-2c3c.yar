rule TTP_XOR_WriteProcessMemory_2c3c {
  strings:
    $key_2c3c = { 7b 4e [2] 49 6c [2] 4f 59 [2] 61 59 [2] 5e 45 }

  condition:
    any of them
}