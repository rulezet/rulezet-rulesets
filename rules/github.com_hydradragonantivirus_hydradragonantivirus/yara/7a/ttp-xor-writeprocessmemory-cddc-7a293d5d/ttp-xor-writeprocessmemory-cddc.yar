rule TTP_XOR_WriteProcessMemory_cddc {
  strings:
    $key_cddc = { 9a ae [2] a8 8c [2] ae b9 [2] 80 b9 [2] bf a5 }

  condition:
    any of them
}