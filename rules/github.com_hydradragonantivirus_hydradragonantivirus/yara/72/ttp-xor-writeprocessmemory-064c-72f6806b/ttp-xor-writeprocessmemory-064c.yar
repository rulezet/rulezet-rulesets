rule TTP_XOR_WriteProcessMemory_064c {
  strings:
    $key_064c = { 51 3e [2] 63 1c [2] 65 29 [2] 4b 29 [2] 74 35 }

  condition:
    any of them
}