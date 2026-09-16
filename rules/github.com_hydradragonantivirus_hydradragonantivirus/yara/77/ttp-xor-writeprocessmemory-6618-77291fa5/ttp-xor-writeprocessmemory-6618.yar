rule TTP_XOR_WriteProcessMemory_6618 {
  strings:
    $key_6618 = { 31 6a [2] 03 48 [2] 05 7d [2] 2b 7d [2] 14 61 }

  condition:
    any of them
}