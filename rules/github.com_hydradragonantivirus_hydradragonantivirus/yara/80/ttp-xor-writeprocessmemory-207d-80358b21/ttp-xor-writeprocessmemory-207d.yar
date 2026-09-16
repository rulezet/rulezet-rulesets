rule TTP_XOR_WriteProcessMemory_207d {
  strings:
    $key_207d = { 77 0f [2] 45 2d [2] 43 18 [2] 6d 18 [2] 52 04 }

  condition:
    any of them
}