rule TTP_XOR_WriteProcessMemory_ef3c {
  strings:
    $key_ef3c = { b8 4e [2] 8a 6c [2] 8c 59 [2] a2 59 [2] 9d 45 }

  condition:
    any of them
}