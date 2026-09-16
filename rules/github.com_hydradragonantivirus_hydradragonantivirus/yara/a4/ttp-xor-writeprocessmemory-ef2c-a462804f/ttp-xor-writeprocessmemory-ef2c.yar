rule TTP_XOR_WriteProcessMemory_ef2c {
  strings:
    $key_ef2c = { b8 5e [2] 8a 7c [2] 8c 49 [2] a2 49 [2] 9d 55 }

  condition:
    any of them
}