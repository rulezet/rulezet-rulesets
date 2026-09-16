rule TTP_XOR_WriteProcessMemory_3fcb {
  strings:
    $key_3fcb = { 68 b9 [2] 5a 9b [2] 5c ae [2] 72 ae [2] 4d b2 }

  condition:
    any of them
}