rule TTP_XOR_WriteProcessMemory_ef0c {
  strings:
    $key_ef0c = { b8 7e [2] 8a 5c [2] 8c 69 [2] a2 69 [2] 9d 75 }

  condition:
    any of them
}