rule TTP_XOR_WriteProcessMemory_0419 {
  strings:
    $key_0419 = { 53 6b [2] 61 49 [2] 67 7c [2] 49 7c [2] 76 60 }

  condition:
    any of them
}