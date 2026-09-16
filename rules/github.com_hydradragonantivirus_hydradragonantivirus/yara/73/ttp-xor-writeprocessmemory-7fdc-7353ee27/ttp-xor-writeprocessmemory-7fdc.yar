rule TTP_XOR_WriteProcessMemory_7fdc {
  strings:
    $key_7fdc = { 28 ae [2] 1a 8c [2] 1c b9 [2] 32 b9 [2] 0d a5 }

  condition:
    any of them
}