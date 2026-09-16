rule TTP_XOR_WriteProcessMemory_f147 {
  strings:
    $key_f147 = { a6 35 [2] 94 17 [2] 92 22 [2] bc 22 [2] 83 3e }

  condition:
    any of them
}