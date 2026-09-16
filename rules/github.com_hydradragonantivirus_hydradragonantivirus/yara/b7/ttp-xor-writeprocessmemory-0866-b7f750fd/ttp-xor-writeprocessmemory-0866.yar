rule TTP_XOR_WriteProcessMemory_0866 {
  strings:
    $key_0866 = { 5f 14 [2] 6d 36 [2] 6b 03 [2] 45 03 [2] 7a 1f }

  condition:
    any of them
}