rule TTP_XOR_WriteProcessMemory_9adb {
  strings:
    $key_9adb = { cd a9 [2] ff 8b [2] f9 be [2] d7 be [2] e8 a2 }

  condition:
    any of them
}