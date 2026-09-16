rule TTP_XOR_WriteProcessMemory_2fdc {
  strings:
    $key_2fdc = { 78 ae [2] 4a 8c [2] 4c b9 [2] 62 b9 [2] 5d a5 }

  condition:
    any of them
}