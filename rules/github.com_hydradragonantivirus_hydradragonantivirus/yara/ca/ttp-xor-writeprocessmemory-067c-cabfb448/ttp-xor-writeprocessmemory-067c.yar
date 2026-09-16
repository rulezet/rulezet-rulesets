rule TTP_XOR_WriteProcessMemory_067c {
  strings:
    $key_067c = { 51 0e [2] 63 2c [2] 65 19 [2] 4b 19 [2] 74 05 }

  condition:
    any of them
}