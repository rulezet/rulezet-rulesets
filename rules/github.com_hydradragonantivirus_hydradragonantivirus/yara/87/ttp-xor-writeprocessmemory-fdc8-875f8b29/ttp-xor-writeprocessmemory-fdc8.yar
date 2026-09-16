rule TTP_XOR_WriteProcessMemory_fdc8 {
  strings:
    $key_fdc8 = { aa ba [2] 98 98 [2] 9e ad [2] b0 ad [2] 8f b1 }

  condition:
    any of them
}