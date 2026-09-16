rule TTP_XOR_WriteProcessMemory_5adb {
  strings:
    $key_5adb = { 0d a9 [2] 3f 8b [2] 39 be [2] 17 be [2] 28 a2 }

  condition:
    any of them
}