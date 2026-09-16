rule TTP_XOR_WriteProcessMemory_0209 {
  strings:
    $key_0209 = { 55 7b [2] 67 59 [2] 61 6c [2] 4f 6c [2] 70 70 }

  condition:
    any of them
}