rule TTP_XOR_WriteProcessMemory_f100 {
  strings:
    $key_f100 = { a6 72 [2] 94 50 [2] 92 65 [2] bc 65 [2] 83 79 }

  condition:
    any of them
}