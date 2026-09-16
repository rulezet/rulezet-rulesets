rule TTP_XOR_WriteProcessMemory_2618 {
  strings:
    $key_2618 = { 71 6a [2] 43 48 [2] 45 7d [2] 6b 7d [2] 54 61 }

  condition:
    any of them
}