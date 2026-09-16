rule TTP_XOR_WriteProcessMemory_7618 {
  strings:
    $key_7618 = { 21 6a [2] 13 48 [2] 15 7d [2] 3b 7d [2] 04 61 }

  condition:
    any of them
}