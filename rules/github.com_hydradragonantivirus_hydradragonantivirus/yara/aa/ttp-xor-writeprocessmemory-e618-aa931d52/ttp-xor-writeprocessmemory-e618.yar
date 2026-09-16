rule TTP_XOR_WriteProcessMemory_e618 {
  strings:
    $key_e618 = { b1 6a [2] 83 48 [2] 85 7d [2] ab 7d [2] 94 61 }

  condition:
    any of them
}