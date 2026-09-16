rule TTP_XOR_WriteProcessMemory_3adb {
  strings:
    $key_3adb = { 6d a9 [2] 5f 8b [2] 59 be [2] 77 be [2] 48 a2 }

  condition:
    any of them
}