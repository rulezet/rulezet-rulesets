rule TTP_XOR_WriteProcessMemory_8adb {
  strings:
    $key_8adb = { dd a9 [2] ef 8b [2] e9 be [2] c7 be [2] f8 a2 }

  condition:
    any of them
}