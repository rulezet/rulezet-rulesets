rule TTP_XOR_WriteProcessMemory_2b01 {
  strings:
    $key_2b01 = { 7c 73 [2] 4e 51 [2] 48 64 [2] 66 64 [2] 59 78 }

  condition:
    any of them
}