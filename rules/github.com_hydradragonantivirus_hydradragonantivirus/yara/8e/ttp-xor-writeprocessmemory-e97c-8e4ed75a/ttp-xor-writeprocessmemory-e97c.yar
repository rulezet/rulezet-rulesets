rule TTP_XOR_WriteProcessMemory_e97c {
  strings:
    $key_e97c = { be 0e [2] 8c 2c [2] 8a 19 [2] a4 19 [2] 9b 05 }

  condition:
    any of them
}