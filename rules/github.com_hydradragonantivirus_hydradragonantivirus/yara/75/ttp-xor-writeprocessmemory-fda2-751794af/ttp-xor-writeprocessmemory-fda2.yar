rule TTP_XOR_WriteProcessMemory_fda2 {
  strings:
    $key_fda2 = { aa d0 [2] 98 f2 [2] 9e c7 [2] b0 c7 [2] 8f db }

  condition:
    any of them
}