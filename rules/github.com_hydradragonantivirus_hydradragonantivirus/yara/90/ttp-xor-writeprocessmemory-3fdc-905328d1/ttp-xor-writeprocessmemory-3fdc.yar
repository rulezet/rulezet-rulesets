rule TTP_XOR_WriteProcessMemory_3fdc {
  strings:
    $key_3fdc = { 68 ae [2] 5a 8c [2] 5c b9 [2] 72 b9 [2] 4d a5 }

  condition:
    any of them
}