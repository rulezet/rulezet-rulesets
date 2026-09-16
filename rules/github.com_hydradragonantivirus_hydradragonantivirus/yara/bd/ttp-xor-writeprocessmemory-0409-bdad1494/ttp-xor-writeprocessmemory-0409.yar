rule TTP_XOR_WriteProcessMemory_0409 {
  strings:
    $key_0409 = { 53 7b [2] 61 59 [2] 67 6c [2] 49 6c [2] 76 70 }

  condition:
    any of them
}