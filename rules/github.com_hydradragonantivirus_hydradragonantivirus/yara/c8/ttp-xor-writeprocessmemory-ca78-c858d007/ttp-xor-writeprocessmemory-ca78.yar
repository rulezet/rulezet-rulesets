rule TTP_XOR_WriteProcessMemory_ca78 {
  strings:
    $key_ca78 = { 9d 0a [2] af 28 [2] a9 1d [2] 87 1d [2] b8 01 }

  condition:
    any of them
}