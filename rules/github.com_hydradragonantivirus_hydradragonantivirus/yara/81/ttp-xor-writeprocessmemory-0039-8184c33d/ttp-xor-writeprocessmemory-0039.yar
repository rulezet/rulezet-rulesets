rule TTP_XOR_WriteProcessMemory_0039 {
  strings:
    $key_0039 = { 57 4b [2] 65 69 [2] 63 5c [2] 4d 5c [2] 72 40 }

  condition:
    any of them
}