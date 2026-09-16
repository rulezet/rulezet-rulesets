rule TTP_XOR_WriteProcessMemory_2adb {
  strings:
    $key_2adb = { 7d a9 [2] 4f 8b [2] 49 be [2] 67 be [2] 58 a2 }

  condition:
    any of them
}