rule TTP_XOR_WriteProcessMemory_2866 {
  strings:
    $key_2866 = { 7f 14 [2] 4d 36 [2] 4b 03 [2] 65 03 [2] 5a 1f }

  condition:
    any of them
}