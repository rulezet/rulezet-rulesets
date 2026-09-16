rule TTP_XOR_WriteProcessMemory_1618 {
  strings:
    $key_1618 = { 41 6a [2] 73 48 [2] 75 7d [2] 5b 7d [2] 64 61 }

  condition:
    any of them
}