rule TTP_XOR_WriteProcessMemory_6804 {
  strings:
    $key_6804 = { 3f 76 [2] 0d 54 [2] 0b 61 [2] 25 61 [2] 1a 7d }

  condition:
    any of them
}