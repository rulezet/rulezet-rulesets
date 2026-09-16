rule TTP_XOR_WriteProcessMemory_027c {
  strings:
    $key_027c = { 55 0e [2] 67 2c [2] 61 19 [2] 4f 19 [2] 70 05 }

  condition:
    any of them
}