rule TTP_XOR_WriteProcessMemory_7519 {
  strings:
    $key_7519 = { 22 6b [2] 10 49 [2] 16 7c [2] 38 7c [2] 07 60 }

  condition:
    any of them
}